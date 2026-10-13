//! The narrow command API between the UI and `usna-vault-core` (docs/ARCHITECTURE.md §2).
//!
//! Rules enforced here: the UI never receives keys; list/detail views carry no secrets; a secret is
//! returned only by `reveal_password` on an explicit user action; copy-to-clipboard happens in Rust;
//! the inactivity lock is a Rust timer, not a UI timer.
//!
//! **Transactions.** Every change to the vault model goes through [`Session::commit`]: mutate the live
//! model (each mutation returns an exact undo token), write the new snapshot, and on any failure revert the
//! model, so the live session always equals the last *committed* snapshot. Files are removed from disk only
//! after the snapshot that no longer references them has been committed. All of this logic lives on
//! `Session` behind the `Backend` trait so it is tested with injected write failures (see the tests).

use std::{
    collections::HashSet,
    fs::File,
    io::{BufWriter, Read, Write},
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;
use usna_vault_core::{
    Error as CoreError, FileKey, Header, KdfParams, ObjectId, ObjectReader, ObjectWriter, Password, UnlockedVault,
    WrappedFileKey, DEFAULT_CHUNK_SIZE,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    model::{
        guess_mime, AccountExportDocument, FileRecord, FileView, FolderView, ItemInput, ItemSummary, ItemView, Model,
        PortableItem, Settings, Undo,
        PREVIEW_MAX_BYTES, PREVIEW_MIMES,
    },
    store::{Backend, Store},
    totp::{self, Algo},
    util::{base64, from_hex, from_hex16, to_hex},
};

/// App-level policy (the core only rejects empty passwords).
const MIN_PASSWORD_CHARS: usize = 12;
const ACCOUNT_EXPORT_FORMAT: &str = "USNA Secure Account Export";
const ACCOUNT_EXPORT_VERSION: u32 = 1;
const MAX_ACCOUNT_EXPORT_BYTES: u64 = 10 * 1024 * 1024;

pub struct Session {
    vault: UnlockedVault,
    backend: Box<dyn Backend>,
    revision: u64,
    model: Model,
    last_activity: Instant,
    /// Holds the exclusive OS lock on the vault folder for as long as the vault is unlocked.
    _lock: File,
}

impl Drop for Session {
    /// Best-effort wipe of the decrypted model. The vault keys wipe themselves on drop.
    fn drop(&mut self) {
        for item in &mut self.model.items {
            item.password.zeroize();
            item.totp_secret.zeroize();
            item.username.zeroize();
            item.notes.zeroize();
            for code in &mut item.recovery_codes {
                code.code.zeroize();
            }
        }
    }
}

fn friendly(e: CoreError) -> String {
    match e {
        CoreError::AuthenticationFailed => "Wrong password, or the vault files were modified or damaged.".to_string(),
        CoreError::UnsupportedVersion(_) => "This vault was created by a newer version of USNA Secure.".to_string(),
        other => other.to_string(),
    }
}

impl Session {
    /// Seal the current model as the next snapshot revision and write it. On any failure nothing is
    /// written and `revision` is unchanged. The JSON buffer is wiped.
    fn persist(&mut self) -> Result<(), String> {
        let json = Zeroizing::new(serde_json::to_vec(&self.model).map_err(|e| e.to_string())?);
        let next = self.revision.checked_add(1).ok_or_else(|| "Revision counter overflow.".to_string())?;
        let blob = self.vault.seal_snapshot(next, &json).map_err(friendly)?;
        self.backend.write_db(&blob)?;
        self.revision = next;
        Ok(())
    }

    /// The only way to change the model. `op` mutates it and returns a result plus an undo token (and must
    /// change nothing when it returns `Err`). If the save fails the mutation is reverted.
    fn commit<T>(&mut self, op: impl FnOnce(&mut Model) -> Result<(T, Undo), String>) -> Result<T, String> {
        let (value, undo) = op(&mut self.model)?;
        match self.persist() {
            Ok(()) => {
                undo.discard();
                Ok(value)
            }
            Err(e) => {
                self.model.revert(undo);
                Err(e)
            }
        }
    }

    fn save_item(&mut self, input: ItemInput) -> Result<u64, String> {
        self.commit(|m| m.upsert(input))
    }
    fn delete_item(&mut self, id: u64) -> Result<(), String> {
        self.commit(|m| m.delete(id).map(|u| ((), u)))
    }
    fn import_accounts(&mut self, records: Vec<PortableItem>) -> Result<usize, String> {
        self.commit(|m| m.import_accounts(records))
    }
    fn add_recovery_codes(&mut self, id: u64, codes: Vec<String>) -> Result<usize, String> {
        self.commit(|m| m.add_recovery_codes(id, codes))
    }
    fn set_recovery_code_used(&mut self, id: u64, index: usize, used: bool) -> Result<(), String> {
        self.commit(|m| m.set_recovery_code_used(id, index, used).map(|u| ((), u)))
    }
    fn delete_recovery_code(&mut self, id: u64, index: usize) -> Result<(), String> {
        self.commit(|m| m.delete_recovery_code(id, index).map(|u| ((), u)))
    }
    fn set_favorite(&mut self, id: u64, favorite: bool) -> Result<(), String> {
        self.commit(|m| m.set_favorite(id, favorite).map(|u| ((), u)))
    }
    fn set_settings(&mut self, settings: Settings) -> Result<(), String> {
        self.commit(|m| Ok(((), m.set_settings(settings))))
    }
    fn create_folder(&mut self, name: &str) -> Result<u64, String> {
        self.commit(|m| m.create_folder(name))
    }
    fn rename_folder(&mut self, id: u64, name: &str) -> Result<(), String> {
        self.commit(|m| m.rename_folder(id, name).map(|u| ((), u)))
    }
    /// Objects are deleted from disk only after the snapshot without their records is committed.
    fn delete_folder(&mut self, id: u64) -> Result<(), String> {
        let objects = self.commit(|m| m.delete_folder(id))?;
        for o in &objects {
            self.backend.remove_object(o);
        }
        Ok(())
    }
    fn add_file_record(&mut self, rec: FileRecord) -> Result<FileView, String> {
        self.commit(|m| m.add_file(rec))
    }
    /// The object is deleted from disk only after the snapshot without its record is committed.
    fn delete_file(&mut self, id: u64) -> Result<(), String> {
        let object = self.commit(|m| m.delete_file(id))?;
        self.backend.remove_object(&object);
        Ok(())
    }

    /// Re-wrap the vault key under a new password. The header is written durably first and adopted in
    /// memory second, so a failed write leaves both the file and the session on the old password.
    fn change_password(&mut self, current: &Password, new: &Password, kdf: KdfParams) -> Result<(), String> {
        let update = self.vault.prepare_password_change(current, new, kdf).map_err(friendly)?;
        self.backend.write_header(&update.bytes())?;
        self.vault.commit_header_update(update).map_err(friendly)
    }

    /// Read-only consistency check of header and snapshot against this session. Runs under the session
    /// lock, so it cannot race with a save.
    fn check_metadata(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let vault_id = *self.vault.vault_id();
        match self.backend.read_header().and_then(|b| Header::parse(&b).map_err(friendly)) {
            Ok(h) => {
                if h.vault_id() != &vault_id {
                    problems.push("vault.header belongs to a different vault.".to_string());
                }
                if h.vk_generation() != self.vault.vk_generation() {
                    problems.push("vault.header has a different key generation than the open vault.".to_string());
                }
            }
            Err(e) => problems.push(format!("vault.header: {e}")),
        }
        match self.backend.read_db() {
            Ok(blob) => match self.vault.open_snapshot(&blob) {
                Ok((rev, _plaintext)) => {
                    if rev != self.revision {
                        problems.push(format!("vault.db is at revision {rev} but this session expected {}.", self.revision));
                    }
                }
                Err(e) => problems.push(format!("vault.db: {}", friendly(e))),
            },
            Err(e) => problems.push(e),
        }
        problems
    }
}

#[derive(Default)]
pub struct AppState {
    session: Mutex<Option<Session>>,
    copied: Mutex<Option<Zeroizing<String>>>,
    failed_unlocks: Mutex<u32>,
    /// Object ids currently being imported (so the integrity check does not call them orphans).
    importing: Mutex<HashSet<String>>,
}

#[derive(Serialize)]
pub struct Status {
    exists: bool,
    unlocked: bool,
}

#[derive(Serialize)]
pub struct TotpNow {
    code: String,
    remaining: u64,
}

#[derive(Serialize)]
pub struct RecoveryCodeView {
    index: usize,
    code: String,
    used: bool,
}

impl Drop for RecoveryCodeView {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}

fn store_for(app: &AppHandle) -> Result<Store, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Cannot find the app data folder: {e}"))?
        .join("vault");
    Ok(Store::new(dir))
}

fn with_session<T>(state: &AppState, f: impl FnOnce(&mut Session) -> Result<T, String>) -> Result<T, String> {
    let mut guard = state.session.lock().map_err(|_| "Internal error (lock poisoned).".to_string())?;
    let session = guard.as_mut().ok_or_else(|| "The vault is locked.".to_string())?;
    session.last_activity = Instant::now();
    f(session)
}

fn clear_clipboard_if_equal(value: &str) {
    if let Ok(mut cb) = arboard::Clipboard::new() {
        if cb.get_text().ok().as_deref() == Some(value) {
            let _ = cb.clear();
        }
    }
}

pub fn lock_now(state: &AppState) {
    if let Ok(mut g) = state.session.lock() {
        *g = None; // drops the session: keys and model are wiped (best effort)
    }
    if let Ok(mut c) = state.copied.lock() {
        if let Some(v) = c.take() {
            clear_clipboard_if_equal(v.as_str());
        }
    }
}

/// Inactivity lock: checked once a second; notifies the UI with the `vault-locked` event.
pub fn spawn_auto_lock(app: AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(1));
        let state = app.state::<AppState>();
        let expired = match state.session.lock() {
            Ok(g) => g.as_ref().is_some_and(|s| {
                let limit = s.model.settings.auto_lock_secs;
                limit > 0 && s.last_activity.elapsed().as_secs() >= limit
            }),
            Err(_) => false,
        };
        if expired {
            lock_now(state.inner());
            let _ = app.emit("vault-locked", "inactivity");
        }
    });
}

// ---- vault lifecycle ---------------------------------------------------------------------------

#[tauri::command]
pub fn vault_status(app: AppHandle, state: State<'_, AppState>) -> Result<Status, String> {
    let exists = store_for(&app)?.exists();
    let unlocked = state.session.lock().map_err(|_| "Internal error.".to_string())?.is_some();
    Ok(Status { exists, unlocked })
}

fn create_inner(app: &AppHandle, state: &AppState, password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!(
            "Use at least {MIN_PASSWORD_CHARS} characters. A passphrase of several random words works well."
        ));
    }
    let store = store_for(app)?;
    if store.exists() {
        return Err("A vault already exists on this computer.".into());
    }
    let pw = Password::new(password).map_err(friendly)?;
    let (vault, header) = UnlockedVault::create(&pw, KdfParams::RECOMMENDED).map_err(friendly)?;
    store.init_dir()?;
    let lock = store.acquire_instance_lock()?;
    store.clean_leftovers();
    let model = Model::default();
    let json = Zeroizing::new(serde_json::to_vec(&model).map_err(|e| e.to_string())?);
    let blob = vault.seal_snapshot(1, &json).map_err(friendly)?;
    // Database first, header last: a crash in between leaves "no vault", never a half vault.
    store.write_db(&blob)?;
    store.write_header(&header)?;
    let mut g = state.session.lock().map_err(|_| "Internal error.".to_string())?;
    *g = Some(Session { vault, backend: Box::new(store), revision: 1, model, last_activity: Instant::now(), _lock: lock });
    Ok(())
}

#[tauri::command]
pub async fn vault_create(app: AppHandle, state: State<'_, AppState>, mut password: String) -> Result<(), String> {
    let r = create_inner(&app, state.inner(), &password);
    password.zeroize();
    r
}

fn unlock_inner(app: &AppHandle, state: &AppState, password: &str) -> Result<(), String> {
    let store = store_for(app)?;
    if !store.exists() {
        return Err("No vault found on this computer.".into());
    }
    let lock = store.acquire_instance_lock()?;
    store.clean_leftovers();
    let pw = Password::new(password).map_err(|_| "Enter your master password.".to_string())?;
    let header = store.read_header()?;
    let vault = UnlockedVault::unlock(&header, &pw).map_err(friendly)?;
    let blob = store.read_db()?;
    let (revision, plaintext) = vault.open_snapshot(&blob).map_err(friendly)?;
    let model: Model = serde_json::from_slice(&plaintext)
        .map_err(|_| "The vault data could not be read (unsupported format).".to_string())?;
    let mut g = state.session.lock().map_err(|_| "Internal error.".to_string())?;
    *g = Some(Session { vault, backend: Box::new(store), revision, model, last_activity: Instant::now(), _lock: lock });
    Ok(())
}

/// Delay after repeated failed unlocks: none for the first two, then 1, 2, 4, 8 s (capped).
/// UI-level friction only: an attacker with the files is limited by Argon2id cost, not by this.
fn backoff_secs(failures: u32) -> u64 {
    if failures < 3 {
        0
    } else {
        1u64 << (failures - 3).min(3)
    }
}

#[tauri::command]
pub async fn vault_unlock(app: AppHandle, state: State<'_, AppState>, mut password: String) -> Result<(), String> {
    let r = unlock_inner(&app, state.inner(), &password);
    password.zeroize();
    if let Ok(mut n) = state.failed_unlocks.lock() {
        if r.is_ok() {
            *n = 0;
        } else {
            *n = n.saturating_add(1);
            let wait = backoff_secs(*n);
            drop(n);
            if wait > 0 {
                std::thread::sleep(Duration::from_secs(wait));
            }
        }
    }
    r
}

#[tauri::command]
pub fn vault_lock(state: State<'_, AppState>) -> Result<(), String> {
    lock_now(state.inner());
    Ok(())
}

fn change_password_inner(state: &AppState, current: &str, new: &str) -> Result<(), String> {
    if new.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!("The new password needs at least {MIN_PASSWORD_CHARS} characters."));
    }
    let cur = Password::new(current).map_err(|_| "Enter your current password.".to_string())?;
    let newp = Password::new(new).map_err(friendly)?;
    with_session(state, |s| s.change_password(&cur, &newp, KdfParams::RECOMMENDED))
}

#[tauri::command]
pub async fn change_password(state: State<'_, AppState>, mut current: String, mut new: String) -> Result<(), String> {
    let r = change_password_inner(state.inner(), &current, &new);
    current.zeroize();
    new.zeroize();
    r
}

#[tauri::command]
pub fn touch(state: State<'_, AppState>) -> Result<(), String> {
    with_session(state.inner(), |_| Ok(()))
}

// ---- items -------------------------------------------------------------------------------------

#[tauri::command]
pub fn list_items(state: State<'_, AppState>) -> Result<Vec<ItemSummary>, String> {
    with_session(state.inner(), |s| Ok(s.model.items.iter().map(|i| i.summary()).collect()))
}

/// Writes a plaintext JSON export only after the UI asks for explicit confirmation.
/// The resulting file contains account secrets and must be protected accordingly.
#[tauri::command]
pub async fn export_accounts(app: AppHandle, state: State<'_, AppState>) -> Result<bool, String> {
    let bytes = with_session(state.inner(), |s| {
        if s.model.items.len() > 1000 {
            return Err("Account export supports at most 1,000 entries.".into());
        }
        let document = AccountExportDocument {
            format: ACCOUNT_EXPORT_FORMAT.to_string(),
            version: ACCOUNT_EXPORT_VERSION,
            items: s.model.items.iter().map(|item| PortableItem {
                kind: item.kind.clone(),
                title: item.title.clone(),
                favorite: item.favorite,
                username: item.username.clone(),
                password: item.password.clone(),
                totp_secret: item.totp_secret.clone(),
                passkey: item.passkey,
                notes: item.notes.clone(),
                recovery_codes: item.recovery_codes.clone(),
            }).collect(),
        };
        serde_json::to_vec_pretty(&document).map(Zeroizing::new)
            .map_err(|_| "Could not serialize account data for export.".to_string())
    })?;
    if bytes.len() as u64 > MAX_ACCOUNT_EXPORT_BYTES {
        return Err("The account export exceeds the 10 MiB size limit.".into());
    }

    let Some(dest) = app.dialog().file()
        .set_file_name("usna-secure-accounts.json")
        .blocking_save_file()
    else {
        return Ok(false);
    };
    let dest = dest.into_path().map_err(|e| format!("Cannot use that location: {e}"))?;
    let write_result = (|| -> std::io::Result<()> {
        let mut output = File::create(&dest)?;
        output.write_all(bytes.as_slice())?;
        output.sync_all()
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&dest);
        return Err(short_io(&e));
    }
    Ok(true)
}

/// Imports an explicit plaintext JSON export as new records. Existing records are never overwritten.
#[tauri::command]
pub async fn import_accounts(app: AppHandle, state: State<'_, AppState>) -> Result<usize, String> {
    let Some(picked) = app.dialog().file()
        .add_filter("USNA Secure account export", &["json"])
        .blocking_pick_file()
    else {
        return Ok(0);
    };
    let path = picked.into_path().map_err(|e| format!("Cannot use that file: {e}"))?;
    let metadata = std::fs::metadata(&path).map_err(|e| short_io(&e))?;
    if metadata.len() > MAX_ACCOUNT_EXPORT_BYTES {
        return Err("The account export exceeds the 10 MiB size limit.".into());
    }
    let input = File::open(&path).map_err(|e| short_io(&e))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    let mut limited = input.take(MAX_ACCOUNT_EXPORT_BYTES + 1);
    limited.read_to_end(&mut bytes).map_err(|e| short_io(&e))?;
    if bytes.len() as u64 > MAX_ACCOUNT_EXPORT_BYTES {
        return Err("The account export exceeds the 10 MiB size limit.".into());
    }

    let mut document: AccountExportDocument = serde_json::from_slice(&bytes)
        .map_err(|_| "The selected file is not a valid USNA Secure account export.".to_string())?;
    if document.format != ACCOUNT_EXPORT_FORMAT || document.version != ACCOUNT_EXPORT_VERSION {
        return Err("This file is not a supported USNA Secure account export.".into());
    }
    let records = std::mem::take(&mut document.items);
    drop(document);
    with_session(state.inner(), |s| s.import_accounts(records))
}



/// Search non-secret metadata in Rust. Passwords, TOTP seeds, recovery codes and file contents are excluded.
#[tauri::command]
pub fn search_items(state: State<'_, AppState>, query: String) -> Result<Vec<ItemSummary>, String> {
    let needle = query.trim().to_lowercase();
    with_session(state.inner(), |s| {
        Ok(s.model.items.iter().filter(|item| item.matches_search(&needle))
            .map(|item| item.summary()).collect())
    })
}

/// Recovery-code values are returned only when the user explicitly opens a specific account's panel.
#[tauri::command]
pub fn get_recovery_codes(state: State<'_, AppState>, id: u64) -> Result<Vec<RecoveryCodeView>, String> {
    with_session(state.inner(), |s| {
        let item = s.model.find(id)?;
        if item.kind != "app" {
            return Err("Recovery codes can only be attached to an app or account.".into());
        }
        Ok(item.recovery_codes.iter().enumerate().map(|(index, code)| RecoveryCodeView {
            index,
            code: code.code.clone(),
            used: code.used,
        }).collect())
    })
}

#[tauri::command]
pub fn add_recovery_codes(state: State<'_, AppState>, id: u64, codes: Vec<String>) -> Result<usize, String> {
    with_session(state.inner(), |s| s.add_recovery_codes(id, codes))
}

#[tauri::command]
pub fn set_recovery_code_used(state: State<'_, AppState>, id: u64, index: usize, used: bool) -> Result<(), String> {
    with_session(state.inner(), |s| s.set_recovery_code_used(id, index, used))
}

#[tauri::command]
pub fn delete_recovery_code(state: State<'_, AppState>, id: u64, index: usize) -> Result<(), String> {
    with_session(state.inner(), |s| s.delete_recovery_code(id, index))
}

#[tauri::command]
pub fn get_item(state: State<'_, AppState>, id: u64) -> Result<ItemView, String> {
    with_session(state.inner(), |s| Ok(s.model.find(id)?.view()))
}

/// The only command that returns a secret, and only on an explicit user action.
#[tauri::command]
pub fn reveal_password(state: State<'_, AppState>, id: u64) -> Result<String, String> {
    with_session(state.inner(), |s| Ok(s.model.find(id)?.password.clone()))
}

#[tauri::command]
pub fn save_item(state: State<'_, AppState>, input: ItemInput) -> Result<u64, String> {
    with_session(state.inner(), |s| s.save_item(input))
}

#[tauri::command]
pub fn delete_item(state: State<'_, AppState>, id: u64) -> Result<(), String> {
    with_session(state.inner(), |s| s.delete_item(id))
}

#[tauri::command]
pub fn set_favorite(state: State<'_, AppState>, id: u64, favorite: bool) -> Result<(), String> {
    with_session(state.inner(), |s| s.set_favorite(id, favorite))
}

// ---- TOTP, clipboard, generator ------------------------------------------------------------------

fn current_code(item_secret: &str) -> Result<(String, u64), String> {
    let secret = Zeroizing::new(
        totp::decode_base32(item_secret).ok_or_else(|| "The authenticator secret is invalid.".to_string())?,
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    let code = totp::totp(&secret, now, 30, Algo::Sha1, 6)
        .ok_or_else(|| "Could not compute a code.".to_string())?;
    Ok((code, 30 - now % 30))
}

#[tauri::command]
pub fn totp_now(state: State<'_, AppState>, id: u64) -> Result<TotpNow, String> {
    with_session(state.inner(), |s| {
        let (code, remaining) = current_code(&s.model.find(id)?.totp_secret)?;
        Ok(TotpNow { code, remaining })
    })
}

#[tauri::command]
pub fn copy_field(
    app: AppHandle,
    state: State<'_, AppState>,
    id: u64,
    field: String,
) -> Result<(), String> {
    let (value, secs) = with_session(state.inner(), |s| {
        let item = s.model.find(id)?;
        let v = match field.as_str() {
            "password" => item.password.clone(),
            "username" => item.username.clone(),
            "totp" => current_code(&item.totp_secret)?.0,
            recovery if recovery.starts_with("recovery:") => {
                let index = recovery["recovery:".len()..].parse::<usize>()
                    .map_err(|_| "Invalid recovery-code index.".to_string())?;
                item.recovery_codes.get(index)
                    .ok_or_else(|| "That recovery code no longer exists.".to_string())?.code.clone()
            }
            _ => return Err("Unknown field.".to_string()),
        };
        Ok((Zeroizing::new(v), s.model.settings.clipboard_clear_secs))
    })?;
    if value.is_empty() {
        return Err("There is nothing to copy.".into());
    }
    let mut cb = arboard::Clipboard::new().map_err(|e| format!("Clipboard unavailable: {e}"))?;
    cb.set_text(value.as_str()).map_err(|e| format!("Could not copy: {e}"))?;
    if let Ok(mut c) = state.copied.lock() {
        *c = Some(value.clone());
    }
    if secs > 0 {
        let handle = app.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(secs));
            clear_clipboard_if_equal(value.as_str()); // only if the clipboard still holds our value
            if let Ok(mut c) = handle.state::<AppState>().copied.lock() {
                *c = None;
            }
        });
    }
    Ok(())
}

fn random_below(n: u32) -> Result<u32, String> {
    // Rejection sampling: no modulo bias.
    let limit = u32::MAX - (u32::MAX % n);
    loop {
        let mut b = [0u8; 4];
        getrandom::getrandom(&mut b).map_err(|_| "The system random generator failed.".to_string())?;
        let x = u32::from_le_bytes(b);
        if x < limit {
            return Ok(x % n);
        }
    }
}

#[tauri::command]
pub fn generate_password(length: usize) -> Result<String, String> {
    const CHARS: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_";
    let len = length.clamp(8, 64);
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        let i = random_below(CHARS.len() as u32)? as usize;
        out.push(char::from(CHARS[i]));
    }
    Ok(out)
}

// ---- settings ----------------------------------------------------------------------------------

#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> Result<Settings, String> {
    with_session(state.inner(), |s| Ok(s.model.settings.clone()))
}

#[tauri::command]
pub fn set_settings(state: State<'_, AppState>, settings: Settings) -> Result<(), String> {
    with_session(state.inner(), |s| s.set_settings(settings))
}

// ---- folders and encrypted files ------------------------------------------------------------------

fn short_io(e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::InvalidData {
        format!("The encrypted file failed its integrity check ({e}).")
    } else {
        format!("File error: {e}")
    }
}

#[tauri::command]
pub fn list_folders(state: State<'_, AppState>) -> Result<Vec<FolderView>, String> {
    with_session(state.inner(), |s| Ok(s.model.folder_views()))
}

#[tauri::command]
pub fn create_folder(state: State<'_, AppState>, name: String) -> Result<u64, String> {
    with_session(state.inner(), |s| s.create_folder(&name))
}

#[tauri::command]
pub fn rename_folder(state: State<'_, AppState>, id: u64, name: String) -> Result<(), String> {
    with_session(state.inner(), |s| s.rename_folder(id, &name))
}

/// Deletes the folder and every file in it: records first (committed), objects only afterwards.
#[tauri::command]
pub fn delete_folder(state: State<'_, AppState>, id: u64) -> Result<(), String> {
    with_session(state.inner(), |s| s.delete_folder(id))
}

#[tauri::command]
pub fn list_files(state: State<'_, AppState>, folder_id: u64) -> Result<Vec<FileView>, String> {
    with_session(state.inner(), |s| {
        Ok(s.model.files.iter().filter(|f| f.folder_id == folder_id).map(|f| f.view()).collect())
    })
}

/// Removes the id from the in-flight set when the import ends, however it ends.
struct InFlight<'a> {
    set: &'a Mutex<HashSet<String>>,
    id: String,
}
impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if let Ok(mut s) = self.set.lock() {
            s.remove(&self.id);
        }
    }
}

/// Pick a file with a native dialog, encrypt it in a streaming fashion into a new object, then record it.
/// `Ok(None)` means the user cancelled.
///
/// Failure handling, step by step: a failed stream deletes the temp file; a failed object commit deletes
/// the temp file; a failed snapshot commit reverts the model (so the file record does not exist) and then
/// removes the object. A crash between the object commit and the snapshot commit leaves one unreferenced
/// object, which "Check vault integrity" reports; there is never a record without its object.
#[tauri::command]
pub async fn import_file(app: AppHandle, state: State<'_, AppState>, folder_id: u64) -> Result<Option<FileView>, String> {
    let Some(picked) = app.dialog().file().blocking_pick_file() else {
        return Ok(None);
    };
    let path = picked.into_path().map_err(|e| format!("Cannot use that file: {e}"))?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "file".to_string());

    // 1. Under the session lock: check the folder, mint the object id and its key.
    let object = ObjectId::generate().map_err(friendly)?;
    let hex = to_hex(object.as_bytes());
    state.importing.lock().map_err(|_| "Internal error.".to_string())?.insert(hex.clone());
    let _in_flight = InFlight { set: &state.importing, id: hex.clone() };
    let (vault_id, key, wrapped) = with_session(state.inner(), |s| {
        if !s.model.has_folder(folder_id) {
            return Err("That folder no longer exists.".to_string());
        }
        let (key, wrapped) = s.vault.new_file_key(&object).map_err(friendly)?;
        Ok((*s.vault.vault_id(), key, wrapped))
    })?;

    // 2. Stream-encrypt without holding the session lock (large files must not freeze the app).
    let store = store_for(&app)?;
    let (file, tmp) = store.begin_object(&hex)?;
    let copied = (|| -> std::io::Result<u64> {
        let mut src = File::open(&path)?;
        let mut w = ObjectWriter::new(BufWriter::new(file), &vault_id, &object, &key, DEFAULT_CHUNK_SIZE)?;
        let n = std::io::copy(&mut src, &mut w)?;
        let out = w.finish()?.into_inner().map_err(|e| e.into_error())?;
        out.sync_all()?;
        Ok(n)
    })();
    let size = match copied {
        Ok(n) => n,
        Err(e) => {
            store.discard_tmp(&tmp);
            return Err(short_io(&e));
        }
    };
    if let Err(e) = store.commit_object(&tmp, &hex) {
        store.discard_tmp(&tmp);
        return Err(e);
    }

    // 3. Record it and commit the snapshot (transactional); undo the object if that fails.
    let rec = FileRecord {
        id: 0,
        folder_id,
        mime: guess_mime(&name).to_string(),
        name,
        size,
        object_id: hex.clone(),
        wrapped_key: to_hex(wrapped.as_bytes()),
    };
    match with_session(state.inner(), |s| s.add_file_record(rec)) {
        Ok(view) => Ok(Some(view)),
        Err(e) => {
            store.remove_object(&hex);
            Err(e)
        }
    }
}

fn file_material(s: &Session, id: u64) -> Result<(FileRecord, ObjectId, FileKey, [u8; 16]), String> {
    let rec = s.model.find_file(id)?.clone();
    let object = ObjectId::from_bytes(from_hex16(&rec.object_id).ok_or_else(|| "Corrupt file record.".to_string())?);
    let wrapped_bytes = from_hex(&rec.wrapped_key).ok_or_else(|| "Corrupt file record.".to_string())?;
    let wrapped = WrappedFileKey::from_slice(&wrapped_bytes).map_err(friendly)?;
    let key = s.vault.unwrap_file_key(&wrapped, &object).map_err(friendly)?;
    Ok((rec, object, key, *s.vault.vault_id()))
}

/// Decrypt to a location the user picks. This writes **plaintext to disk** by explicit request.
#[tauri::command]
pub async fn export_file(app: AppHandle, state: State<'_, AppState>, id: u64) -> Result<bool, String> {
    let (rec, object, key, vault_id) = with_session(state.inner(), |s| file_material(s, id))?;
    let Some(dest) = app.dialog().file().set_file_name(rec.name.clone()).blocking_save_file() else {
        return Ok(false);
    };
    let dest = dest.into_path().map_err(|e| format!("Cannot use that location: {e}"))?;
    let store = store_for(&app)?;
    let copied = (|| -> std::io::Result<()> {
        let src = store.open_object(&rec.object_id).map_err(std::io::Error::other)?;
        let mut r = ObjectReader::open(src, &vault_id, &object, &key)?;
        let mut out = File::create(&dest)?;
        std::io::copy(&mut r, &mut out)?;
        out.sync_all()
    })();
    if let Err(e) = copied {
        let _ = std::fs::remove_file(&dest); // never leave a partial plaintext file behind
        return Err(short_io(&e));
    }
    Ok(true)
}

/// Inline preview for common image types only, capped in size. Returns a `data:` URL.
#[tauri::command]
pub async fn preview_file(app: AppHandle, state: State<'_, AppState>, id: u64) -> Result<String, String> {
    let (rec, object, key, vault_id) = with_session(state.inner(), |s| file_material(s, id))?;
    if !PREVIEW_MIMES.contains(&rec.mime.as_str()) {
        return Err("This file type cannot be previewed. Use Export.".into());
    }
    if rec.size > PREVIEW_MAX_BYTES {
        return Err("This image is too large to preview. Use Export.".into());
    }
    let store = store_for(&app)?;
    let src = store.open_object(&rec.object_id)?;
    let mut r = ObjectReader::open(src, &vault_id, &object, &key).map_err(|e| short_io(&e))?;
    let mut bytes = Zeroizing::new(Vec::new());
    r.read_to_end(&mut bytes).map_err(|e| short_io(&e))?;
    Ok(format!("data:{};base64,{}", rec.mime, base64(&bytes)))
}

/// The record is removed and committed first; the object is deleted only after that commit succeeds.
#[tauri::command]
pub fn delete_file(state: State<'_, AppState>, id: u64) -> Result<(), String> {
    with_session(state.inner(), |s| s.delete_file(id))
}

#[derive(Serialize)]
pub struct VerifyReport {
    ok: bool,
    files_checked: usize,
    orphans: usize,
    problems: Vec<String>,
}

/// Integrity check ("vault verify"), read-only. Header and snapshot are checked under the session lock
/// (no race with a save); each file object is then fully authenticated outside the lock. It is a
/// point-in-time report: run it while the app is idle, because a delete that happens during the scan can
/// make an object look unreferenced. Objects of imports in progress are excluded from the orphan count.
#[tauri::command]
pub async fn verify_vault(app: AppHandle, state: State<'_, AppState>) -> Result<VerifyReport, String> {
    let store = store_for(&app)?;
    type Material = Option<(ObjectId, FileKey)>;
    let (vault_id, files, mut problems) = with_session(state.inner(), |s| {
        let problems = s.check_metadata();
        let mut files: Vec<(FileRecord, Material)> = Vec::new();
        for f in &s.model.files {
            match file_material(s, f.id) {
                Ok((rec, object, key, _)) => files.push((rec, Some((object, key)))),
                Err(_) => files.push((f.clone(), None)),
            }
        }
        Ok((*s.vault.vault_id(), files, problems))
    })?;

    for (rec, material) in &files {
        let Some((object, key)) = material else {
            problems.push(format!("File '{}': its key could not be unwrapped.", rec.name));
            continue;
        };
        let checked = store
            .open_object(&rec.object_id)
            .and_then(|f| ObjectReader::open(f, &vault_id, object, key).map_err(|e| short_io(&e)))
            .and_then(|mut r| r.verify_all().map_err(|e| short_io(&e)));
        match checked {
            Ok(n) if n != rec.size => {
                problems.push(format!("File '{}': size {n} does not match the recorded size {}.", rec.name, rec.size));
            }
            Ok(_) => {}
            Err(e) => problems.push(format!("File '{}': {e}", rec.name)),
        }
    }

    // Order matters: in-flight snapshot, then the directory listing, then the referenced set, so an
    // import that finishes in between is counted as referenced rather than orphaned.
    let in_flight: HashSet<String> = state.importing.lock().map(|g| g.clone()).unwrap_or_default();
    let on_disk = store.list_objects();
    let referenced: HashSet<String> =
        with_session(state.inner(), |s| Ok(s.model.files.iter().map(|f| f.object_id.clone()).collect()))?;
    let orphans = on_disk.iter().filter(|id| !referenced.contains(*id) && !in_flight.contains(*id)).count();
    if orphans > 0 {
        problems.push(format!(
            "{orphans} unreferenced encrypted file(s) on disk (left by an interrupted import or delete). They are unreadable without a key and harmless."
        ));
    }
    Ok(VerifyReport { ok: problems.is_empty(), files_checked: files.len(), orphans, problems })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
        Arc,
    };

    // ---- unchanged behaviour ---------------------------------------------------------------------

    #[test]
    fn unlock_backoff_schedule() {
        let waits: Vec<u64> = (0..9).map(backoff_secs).collect();
        assert_eq!(waits, vec![0, 0, 0, 1, 2, 4, 8, 8, 8]);
    }

    #[test]
    fn generated_passwords_have_requested_length_and_vary() {
        let a = generate_password(24).unwrap();
        let b = generate_password(24).unwrap();
        assert_eq!(a.len(), 24);
        assert_ne!(a, b);
        assert_eq!(generate_password(1).unwrap().len(), 8);
        assert_eq!(generate_password(500).unwrap().len(), 64);
    }

    #[test]
    fn random_below_stays_in_range() {
        for _ in 0..1000 {
            assert!(random_below(7).unwrap() < 7);
        }
    }

    #[test]
    fn totp_secret_roundtrip() {
        let (code, remaining) = current_code("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(code.len(), 6);
        assert!((1..=30).contains(&remaining));
        assert!(current_code("not base32!").is_err());
    }

    // ---- transactional persistence under injected write failures --------------------------------------

    #[derive(Default)]
    struct Disk {
        db: Option<Vec<u8>>,
        header: Option<Vec<u8>>,
        events: Vec<String>,
    }

    /// An in-memory "disk" whose writes can be made to fail on demand.
    #[derive(Clone, Default)]
    struct TestBackend {
        disk: Arc<Mutex<Disk>>,
        fail_db: Arc<AtomicBool>,
        fail_header: Arc<AtomicBool>,
    }

    impl Backend for TestBackend {
        fn write_db(&self, bytes: &[u8]) -> Result<(), String> {
            let mut d = self.disk.lock().unwrap();
            if self.fail_db.load(SeqCst) {
                d.events.push("write_db FAILED".into());
                return Err("simulated disk failure".into());
            }
            d.db = Some(bytes.to_vec());
            d.events.push("write_db".into());
            Ok(())
        }
        fn write_header(&self, bytes: &[u8]) -> Result<(), String> {
            let mut d = self.disk.lock().unwrap();
            if self.fail_header.load(SeqCst) {
                d.events.push("write_header FAILED".into());
                return Err("simulated disk failure".into());
            }
            d.header = Some(bytes.to_vec());
            d.events.push("write_header".into());
            Ok(())
        }
        fn read_header(&self) -> Result<Vec<u8>, String> {
            self.disk.lock().unwrap().header.clone().ok_or_else(|| "no header".to_string())
        }
        fn read_db(&self) -> Result<Vec<u8>, String> {
            self.disk.lock().unwrap().db.clone().ok_or_else(|| "no database".to_string())
        }
        fn remove_object(&self, hex: &str) {
            self.disk.lock().unwrap().events.push(format!("remove {hex}"));
        }
    }

    impl TestBackend {
        fn fail(&self, on: bool) {
            self.fail_db.store(on, SeqCst);
        }
        fn events(&self) -> Vec<String> {
            self.disk.lock().unwrap().events.clone()
        }
        fn removed(&self) -> Vec<String> {
            self.events().into_iter().filter(|e| e.starts_with("remove ")).collect()
        }
    }

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn make_session(b: &TestBackend) -> Session {
        let pw = Password::new("test password 12345").unwrap();
        let (vault, header) = UnlockedVault::create(&pw, KdfParams::INSECURE_TEST).unwrap();
        b.disk.lock().unwrap().header = Some(header);
        let path = std::env::temp_dir().join(format!("usna-session-test-{}-{}", std::process::id(), COUNTER.fetch_add(1, SeqCst)));
        let lock = File::create(path).unwrap();
        let mut s = Session {
            vault,
            backend: Box::new(b.clone()),
            revision: 0,
            model: Model::default(),
            last_activity: Instant::now(),
            _lock: lock,
        };
        s.persist().unwrap(); // baseline snapshot, revision 1, on the "disk"
        s
    }

    fn live(s: &Session) -> String {
        serde_json::to_string(&s.model).unwrap()
    }

    /// Decrypts what is actually on the "disk" and returns (revision, model as JSON).
    fn on_disk(s: &Session, b: &TestBackend) -> (u64, String) {
        let blob = b.disk.lock().unwrap().db.clone().unwrap();
        let (rev, plaintext) = s.vault.open_snapshot(&blob).unwrap();
        let m: Model = serde_json::from_slice(&plaintext).unwrap();
        (rev, serde_json::to_string(&m).unwrap())
    }

    /// The core invariant: the live session equals the last committed snapshot.
    fn assert_consistent(s: &Session, b: &TestBackend) {
        let (rev, disk_json) = on_disk(s, b);
        assert_eq!(rev, s.revision, "session revision must equal the committed revision");
        assert_eq!(live(s), disk_json, "live model must equal the last committed snapshot");
    }

    fn file(folder: u64, name: &str, obj: &str) -> FileRecord {
        FileRecord { folder_id: folder, name: name.into(), mime: "application/pdf".into(), size: 1, object_id: obj.repeat(32), ..FileRecord::default() }
    }

    fn item(title: &str, password: &str) -> ItemInput {
        ItemInput { id: None, kind: "app".into(), title: title.into(), username: "u".into(), password: Some(password.into()), totp_secret: None, passkey: false, notes: String::new() }
    }

    #[test]
    fn failed_create_folder_changes_nothing_and_consumes_no_id() {
        let b = TestBackend::default();
        let mut s = make_session(&b);
        let (before, rev) = (live(&s), s.revision);
        b.fail(true);
        assert!(s.create_folder("Taxes").is_err());
        assert_eq!(live(&s), before);
        assert_eq!(s.revision, rev, "a failed save does not advance the revision");
        assert_consistent(&s, &b);
        b.fail(false);
        assert_eq!(s.create_folder("Taxes").unwrap(), 5, "the failed attempt did not burn folder id 5");
        assert_consistent(&s, &b);
    }

    #[test]
    fn failed_rename_folder_keeps_the_old_name() {
        let b = TestBackend::default();
        let mut s = make_session(&b);
        b.fail(true);
        assert!(s.rename_folder(1, "Renamed").is_err());
        assert_eq!(s.model.folders[0].name, "Private Images");
        assert_consistent(&s, &b);
        b.fail(false);
        s.rename_folder(1, "Renamed").unwrap();
        assert_consistent(&s, &b);
    }

    #[test]
    fn failed_folder_deletion_keeps_folder_and_files_and_deletes_no_objects() {
        let b = TestBackend::default();
        let mut s = make_session(&b);
        for (folder, name, obj) in [(4, "a", "a"), (1, "c", "c"), (4, "b", "b")] {
            s.add_file_record(file(folder, name, obj)).unwrap();
        }
        let before = live(&s);

        b.fail(true);
        assert!(s.delete_folder(4).is_err());
        assert_eq!(live(&s), before, "folder, file records and their order are intact");
        assert_eq!(s.model.files.len(), 3);
        assert!(b.removed().is_empty(), "no object may be deleted when the commit failed");
        assert_consistent(&s, &b);

        // Requirement: the failed deletion must not make the file records vanish from a LATER save.
        b.fail(false);
        s.create_folder("Unrelated").unwrap();
        assert_eq!(s.model.files.len(), 3);
        let (_, disk_json) = on_disk(&s, &b);
        let disk: Model = serde_json::from_str(&disk_json).unwrap();
        assert_eq!(disk.files.len(), 3, "the committed snapshot still references all three files");
        assert!(disk.folders.iter().any(|f| f.id == 4));
        assert!(b.removed().is_empty());

        // And a successful deletion removes objects only after the commit.
        s.delete_folder(4).unwrap();
        assert_eq!(s.model.files.len(), 1);
        assert_consistent(&s, &b);
        let events = b.events();
        let last_write = events.iter().rposition(|e| e == "write_db").unwrap();
        let first_remove = events.iter().position(|e| e.starts_with("remove ")).unwrap();
        assert!(last_write < first_remove, "objects are removed after the snapshot commit: {events:?}");
        let mut removed = b.removed();
        removed.sort();
        assert_eq!(removed, vec![format!("remove {}", "a".repeat(32)), format!("remove {}", "b".repeat(32))]);
    }

    #[test]
    fn failed_file_deletion_keeps_the_record_and_the_object() {
        let b = TestBackend::default();
        let mut s = make_session(&b);
        s.add_file_record(file(1, "x", "1")).unwrap();
        s.add_file_record(file(1, "y", "2")).unwrap();
        let before = live(&s);
        b.fail(true);
        assert!(s.delete_file(1).is_err());
        assert_eq!(live(&s), before);
        assert!(b.removed().is_empty());
        assert_consistent(&s, &b);
        b.fail(false);
        s.delete_file(1).unwrap();
        assert_eq!(s.model.files.len(), 1);
        assert_consistent(&s, &b);
        let events = b.events();
        assert_eq!(events.last().unwrap(), &format!("remove {}", "1".repeat(32)));
        assert_eq!(events[events.len() - 2], "write_db", "the commit comes immediately before the removal");
    }

    #[test]
    fn failed_import_commit_leaves_no_record_and_does_not_burn_a_file_id() {
        let b = TestBackend::default();
        let mut s = make_session(&b);
        b.fail(true);
        assert!(s.add_file_record(file(1, "a", "1")).is_err());
        assert!(s.model.files.is_empty());
        assert_eq!(s.model.next_file_id, 1, "the counter is restored too");
        assert_consistent(&s, &b);
        b.fail(false);
        assert_eq!(s.add_file_record(file(1, "a", "1")).unwrap().id, 1);
        assert_consistent(&s, &b);
        // a record for a folder that does not exist is rejected without side effects
        let before = live(&s);
        assert!(s.add_file_record(file(999, "z", "9")).is_err());
        assert_eq!(live(&s), before);
    }

    #[test]
    fn failed_item_operations_are_all_reverted() {
        let b = TestBackend::default();
        let mut s = make_session(&b);
        let id = s.save_item(item("GitHub", "old-password")).unwrap();
        s.save_item(item("Second", "pw2")).unwrap();
        let before = live(&s);

        b.fail(true);
        assert!(s.save_item(item("Brand new", "x")).is_err());
        assert_eq!(s.model.next_id, 3, "a failed create does not consume an id");

        let mut edit = item("Edited title", "NEW-password");
        edit.id = Some(id);
        assert!(s.save_item(edit).is_err());
        assert_eq!(s.model.find(id).unwrap().password, "old-password", "a failed edit keeps the old secret");
        assert_eq!(s.model.find(id).unwrap().title, "GitHub");

        assert!(s.delete_item(id).is_err());
        assert_eq!(s.model.items[0].id, id, "a failed delete keeps the item, in place");
        assert!(s.set_favorite(id, true).is_err());
        assert!(!s.model.find(id).unwrap().favorite);
        assert!(s.set_settings(Settings { auto_lock_secs: 0, clipboard_clear_secs: 90 }).is_err());
        assert_eq!(s.model.settings.auto_lock_secs, 300);

        assert_eq!(live(&s), before, "every failed operation left the model byte-identical");
        assert_consistent(&s, &b);

        b.fail(false);
        s.delete_item(id).unwrap();
        s.set_settings(Settings { auto_lock_secs: 0, clipboard_clear_secs: 90 }).unwrap();
        assert_consistent(&s, &b);
    }

    #[test]
    fn failed_bulk_account_import_restores_the_committed_snapshot() {
        let b = TestBackend::default();
        let mut s = make_session(&b);
        let before = live(&s);
        let record = || PortableItem {
            kind: "app".into(),
            title: "Imported account".into(),
            favorite: true,
            username: "user@example.test".into(),
            password: "imported-secret".into(),
            totp_secret: String::new(),
            passkey: false,
            notes: "imported note".into(),
            recovery_codes: vec![RecoveryCode { code: "recovery-secret".into(), used: false }],
        };

        b.fail(true);
        assert!(s.import_accounts(vec![record()]).is_err());
        assert_eq!(live(&s), before, "a failed bulk save must remove every imported record");
        assert_eq!(s.model.next_id, 1, "a failed bulk save must not consume IDs");
        assert_consistent(&s, &b);

        b.fail(false);
        assert_eq!(s.import_accounts(vec![record()]).unwrap(), 1);
        assert_eq!(s.model.items.len(), 1);
        assert_eq!(s.model.items[0].recovery_codes[0].code, "recovery-secret");
        assert_consistent(&s, &b);
    }

    #[test]
    fn failed_recovery_code_mutations_restore_the_committed_snapshot() {
        let b = TestBackend::default();
        let mut s = make_session(&b);
        let id = s.save_item(item("Discord", "pw")).unwrap();
        s.add_recovery_codes(id, vec!["alpha-code".into(), "beta-code".into()]).unwrap();
        let before = live(&s);

        b.fail(true);
        assert!(s.add_recovery_codes(id, vec!["new-code".into()]).is_err());
        assert!(s.set_recovery_code_used(id, 0, true).is_err());
        assert!(s.delete_recovery_code(id, 0).is_err());
        assert_eq!(live(&s), before, "failed recovery-code writes restore values and used state");
        assert_consistent(&s, &b);

        b.fail(false);
        s.set_recovery_code_used(id, 0, true).unwrap();
        assert_eq!(s.model.find(id).unwrap().view().recovery_codes_remaining, 1);
        assert_consistent(&s, &b);
    }

    #[test]
    fn revision_advances_only_on_successful_saves() {
        let b = TestBackend::default();
        let mut s = make_session(&b);
        assert_eq!(s.revision, 1);
        s.create_folder("A").unwrap();
        assert_eq!(s.revision, 2);
        b.fail(true);
        for _ in 0..3 {
            assert!(s.create_folder("B").is_err());
        }
        assert_eq!(s.revision, 2);
        b.fail(false);
        s.create_folder("B").unwrap();
        assert_eq!(s.revision, 3);
        assert_consistent(&s, &b);
    }

    #[test]
    fn rejected_operations_do_not_write_anything() {
        let b = TestBackend::default();
        let mut s = make_session(&b);
        let writes = b.events().len();
        assert!(s.create_folder("  ").is_err());
        assert!(s.delete_file(42).is_err());
        assert!(s.delete_folder(42).is_err());
        assert!(s.rename_folder(42, "x").is_err());
        assert_eq!(b.events().len(), writes, "validation failures must not touch the disk");
    }

    #[test]
    fn failed_header_write_keeps_the_old_password_everywhere() {
        let b = TestBackend::default();
        let mut s = make_session(&b);
        let old_header = s.vault.header_bytes();
        let cur = Password::new("test password 12345").unwrap();
        let new = Password::new("another password 678").unwrap();

        b.fail_header.store(true, SeqCst);
        assert!(s.change_password(&cur, &new, KdfParams::INSECURE_TEST).is_err());
        assert_eq!(s.vault.header_bytes(), old_header, "session still holds the old header");
        assert_eq!(b.disk.lock().unwrap().header.as_deref(), Some(&old_header[..]), "disk still holds the old header");
        // and the old password still works for another change (re-authentication uses the old header)
        b.fail_header.store(false, SeqCst);
        s.change_password(&cur, &new, KdfParams::INSECURE_TEST).unwrap();
        let new_header = s.vault.header_bytes();
        assert_ne!(new_header, old_header);
        assert_eq!(b.disk.lock().unwrap().header.as_deref(), Some(&new_header[..]));
        assert!(UnlockedVault::unlock(&new_header, &new).is_ok());
        assert!(UnlockedVault::unlock(&new_header, &cur).is_err());
    }

    #[test]
    fn integrity_check_reports_real_problems_and_stays_quiet_when_healthy() {
        let b = TestBackend::default();
        let mut s = make_session(&b);
        s.create_folder("A").unwrap();
        assert!(s.check_metadata().is_empty(), "healthy vault: {:?}", s.check_metadata());

        // a stale or foreign database: a different revision than the session expects
        let stale = s.vault.seal_snapshot(99, b"{}").unwrap();
        b.disk.lock().unwrap().db = Some(stale);
        assert!(s.check_metadata().iter().any(|p| p.contains("revision 99")));

        // a corrupted database fails authentication
        let mut corrupt = s.vault.seal_snapshot(s.revision, b"{}").unwrap();
        let mid = corrupt.len() / 2;
        corrupt[mid] ^= 1;
        b.disk.lock().unwrap().db = Some(corrupt);
        assert!(s.check_metadata().iter().any(|p| p.starts_with("vault.db")));

        // a header from another vault
        let other = UnlockedVault::create(&Password::new("some other password 1").unwrap(), KdfParams::INSECURE_TEST).unwrap().1;
        b.disk.lock().unwrap().header = Some(other);
        assert!(s.check_metadata().iter().any(|p| p.contains("different vault")));
    }
}
