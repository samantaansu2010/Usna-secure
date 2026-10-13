//! Interim application data model (a simplified slice of docs/DATA_MODEL.md, milestone 4).
//! Serialized as JSON and sealed inside the vault snapshot; nothing here is ever written unencrypted.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::totp;

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Settings {
    /// 0 means never.
    pub auto_lock_secs: u64,
    pub clipboard_clear_secs: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self { auto_lock_secs: 300, clipboard_clear_secs: 20 }
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct Item {
    pub id: u64,
    /// "app" or "note"
    pub kind: String,
    pub title: String,
    pub favorite: bool,
    pub username: String,
    pub password: String,
    /// Base32 TOTP secret as entered; empty means none.
    pub totp_secret: String,
    /// Record only: the app does not act as a passkey authenticator (docs/DATA_MODEL.md).
    pub passkey: bool,
    pub notes: String,
    /// Recovery codes are sealed with this account inside the encrypted snapshot.
    pub recovery_codes: Vec<RecoveryCode>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct RecoveryCode {
    pub code: String,
    pub used: bool,
}

impl RecoveryCode {
    fn wipe(&mut self) {
        self.code.zeroize();
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct Folder {
    pub id: u64,
    pub name: String,
}

/// Metadata of one encrypted file. The name, type and wrapped key live only inside the sealed snapshot;
/// the file contents are a separate encrypted object (docs/FILE_FORMAT.md).
#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct FileRecord {
    pub id: u64,
    pub folder_id: u64,
    pub name: String,
    pub mime: String,
    pub size: u64,
    /// 32 hex characters; also the object's file name on disk.
    pub object_id: String,
    /// Hex of the 72-byte wrapped file key.
    pub wrapped_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct Model {
    pub schema: u32,
    pub next_id: u64,
    pub items: Vec<Item>,
    pub settings: Settings,
    pub next_folder_id: u64,
    pub folders: Vec<Folder>,
    pub next_file_id: u64,
    pub files: Vec<FileRecord>,
}
impl Default for Model {
    fn default() -> Self {
        let names = ["Private Images", "Private Videos", "Recovery Codes", "Documents"];
        Self {
            schema: 1,
            next_id: 1,
            items: Vec::new(),
            settings: Settings::default(),
            next_folder_id: names.len() as u64 + 1,
            folders: names.iter().enumerate().map(|(i, n)| Folder { id: i as u64 + 1, name: (*n).to_string() }).collect(),
            next_file_id: 1,
            files: Vec::new(),
        }
    }
}

#[derive(Serialize)]
pub struct FolderView {
    pub id: u64,
    pub name: String,
    pub count: usize,
}

#[derive(Serialize)]
pub struct FileView {
    pub id: u64,
    pub folder_id: u64,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub previewable: bool,
}

/// Image types shown inline. SVG is deliberately excluded.
pub const PREVIEW_MIMES: [&str; 4] = ["image/png", "image/jpeg", "image/gif", "image/webp"];
/// Larger images must be exported instead of previewed (the preview travels through the WebView).
pub const PREVIEW_MAX_BYTES: u64 = 25 * 1024 * 1024;

pub fn guess_mime(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "webm" => "video/webm",
        "txt" | "md" => "text/plain",
        _ => "application/octet-stream",
    }
}

impl FileRecord {
    pub fn view(&self) -> FileView {
        FileView {
            id: self.id,
            folder_id: self.folder_id,
            name: self.name.clone(),
            mime: self.mime.clone(),
            size: self.size,
            previewable: PREVIEW_MIMES.contains(&self.mime.as_str()) && self.size <= PREVIEW_MAX_BYTES,
        }
    }
}

// ---- DTOs: what crosses the IPC boundary. Secrets are never in list or detail views. -------------

#[derive(Serialize)]
pub struct ItemSummary {
    pub id: u64,
    pub kind: String,
    pub title: String,
    pub favorite: bool,
    pub subtitle: String,
}

#[derive(Serialize)]
pub struct ItemView {
    pub id: u64,
    pub kind: String,
    pub title: String,
    pub favorite: bool,
    pub username: String,
    pub has_password: bool,
    pub password_len: usize,
    pub has_totp: bool,
    pub passkey: bool,
    pub notes: String,
    /// Counts only. Code values leave Rust only on an explicit reveal command.
    pub recovery_code_count: usize,
    pub recovery_codes_remaining: usize,
}

#[derive(Deserialize)]
pub struct ItemInput {
    pub id: Option<u64>,
    pub kind: String,
    pub title: String,
    pub username: String,
    /// `None` keeps the current value when editing.
    pub password: Option<String>,
    pub totp_secret: Option<String>,
    pub passkey: bool,
    pub notes: String,
}

impl Item {
    pub fn summary(&self) -> ItemSummary {
        ItemSummary {
            id: self.id,
            kind: self.kind.clone(),
            title: self.title.clone(),
            favorite: self.favorite,
            subtitle: if self.kind == "note" { "Secure note".into() } else { self.username.clone() },
        }
    }
    pub fn view(&self) -> ItemView {
        ItemView {
            id: self.id,
            kind: self.kind.clone(),
            title: self.title.clone(),
            favorite: self.favorite,
            username: self.username.clone(),
            has_password: !self.password.is_empty(),
            password_len: self.password.chars().count(),
            has_totp: !self.totp_secret.is_empty(),
            passkey: self.passkey,
            notes: self.notes.clone(),
            recovery_code_count: self.recovery_codes.len(),
            recovery_codes_remaining: self.recovery_codes.iter().filter(|code| !code.used).count(),
        }
    }
}

/// Exactly what is needed to undo one model mutation. Values are *moved* into the token, not copied; the
/// only duplicate of secret data is the previous value of one `Item` that is being edited.
/// On success call [`Undo::discard`] (wipes any secrets the token holds); on a failed save call
/// [`Model::revert`].
pub enum Undo {
    Settings(Settings),
    PopItem { id: u64, next_id: u64 },
    RestoreItem(Item),
    ReinsertItem { index: usize, item: Item },
    RestoreRecoveryCode { item_id: u64, index: usize, code: RecoveryCode },
    Favorite { id: u64, old: bool },
    PopFolder { id: u64, next_folder_id: u64 },
    RenameFolder { id: u64, old: String },
    ReinsertFolder { index: usize, folder: Folder, files: Vec<(usize, FileRecord)> },
    PopFile { id: u64, next_file_id: u64 },
    ReinsertFile { index: usize, rec: FileRecord },
}

fn wipe_item(it: &mut Item) {
    it.password.zeroize();
    it.totp_secret.zeroize();
    it.username.zeroize();
    it.notes.zeroize();
    for code in &mut it.recovery_codes {
        code.wipe();
    }
}

impl Undo {
    /// The change was committed: the token is no longer needed. Wipe any secrets it still holds.
    pub fn discard(self) {
        match self {
            Undo::RestoreItem(mut it) | Undo::ReinsertItem { item: mut it, .. } => wipe_item(&mut it),
            Undo::RestoreRecoveryCode { mut code, .. } => code.wipe(),
            _ => {}
        }
    }
}

impl Model {
    pub fn find(&self, id: u64) -> Result<&Item, String> {
        self.items.iter().find(|i| i.id == id).ok_or_else(|| "That item no longer exists.".to_string())
    }
    fn find_mut(&mut self, id: u64) -> Result<&mut Item, String> {
        self.items.iter_mut().find(|i| i.id == id).ok_or_else(|| "That item no longer exists.".to_string())
    }

    /// Put the model back exactly as it was before the mutation that produced `undo`.
    pub fn revert(&mut self, undo: Undo) {
        match undo {
            Undo::Settings(old) => self.settings = old,
            Undo::PopItem { id, next_id } => {
                if let Some(pos) = self.items.iter().position(|i| i.id == id) {
                    let mut it = self.items.remove(pos);
                    wipe_item(&mut it);
                }
                self.next_id = next_id;
            }
            Undo::RestoreItem(old) => {
                if let Some(slot) = self.items.iter_mut().find(|i| i.id == old.id) {
                    let mut replaced = std::mem::replace(slot, old);
                    wipe_item(&mut replaced);
                }
            }
            Undo::ReinsertItem { index, item } => {
                let at = index.min(self.items.len());
                self.items.insert(at, item);
            }
            Undo::RestoreRecoveryCode { item_id, index, mut code } => {
                if let Some(item) = self.items.iter_mut().find(|item| item.id == item_id) {
                    let at = index.min(item.recovery_codes.len());
                    item.recovery_codes.insert(at, code);
                } else {
                    code.wipe();
                }
            }
            Undo::Favorite { id, old } => {
                if let Some(it) = self.items.iter_mut().find(|i| i.id == id) {
                    it.favorite = old;
                }
            }
            Undo::PopFolder { id, next_folder_id } => {
                self.folders.retain(|f| f.id != id);
                self.next_folder_id = next_folder_id;
            }
            Undo::RenameFolder { id, old } => {
                if let Some(f) = self.folders.iter_mut().find(|f| f.id == id) {
                    f.name = old;
                }
            }
            Undo::ReinsertFolder { index, folder, files } => {
                let at = index.min(self.folders.len());
                self.folders.insert(at, folder);
                // Original indices are ascending, so re-inserting in order restores the exact sequence.
                for (i, rec) in files {
                    let at = i.min(self.files.len());
                    self.files.insert(at, rec);
                }
            }
            Undo::PopFile { id, next_file_id } => {
                self.files.retain(|f| f.id != id);
                self.next_file_id = next_file_id;
            }
            Undo::ReinsertFile { index, rec } => {
                let at = index.min(self.files.len());
                self.files.insert(at, rec);
            }
        }
    }

    /// Create or update. Validation happens before any change, so an `Err` means nothing was modified.
    pub fn upsert(&mut self, input: ItemInput) -> Result<(u64, Undo), String> {
        let title = input.title.trim().to_string();
        if title.is_empty() {
            return Err("Give the item a name.".into());
        }
        if input.kind != "app" && input.kind != "note" {
            return Err("Unknown item type.".into());
        }
        if let Some(secret) = input.totp_secret.as_deref() {
            if !secret.is_empty() && totp::decode_base32(secret).is_none() {
                return Err("The authenticator secret is not valid Base32 (at least 10 bytes).".into());
            }
        }
        let apply = |it: &mut Item| {
            it.kind = input.kind.clone();
            it.title = title.clone();
            it.username = input.username.clone();
            if let Some(p) = &input.password {
                it.password = p.clone();
            }
            if let Some(t) = &input.totp_secret {
                it.totp_secret = t.clone();
            }
            it.passkey = input.passkey;
            it.notes = input.notes.clone();
        };
        match input.id {
            Some(id) => {
                let old = self.find(id)?.clone();
                apply(self.find_mut(id)?);
                Ok((id, Undo::RestoreItem(old)))
            }
            None => {
                let prev_next = self.next_id;
                let id = prev_next;
                self.next_id += 1;
                let mut it = Item { id, ..Item::default() };
                apply(&mut it);
                self.items.push(it);
                Ok((id, Undo::PopItem { id, next_id: prev_next }))
            }
        }
    }

    pub fn delete(&mut self, id: u64) -> Result<Undo, String> {
        let index = self.items.iter().position(|i| i.id == id).ok_or_else(|| "That item no longer exists.".to_string())?;
        let item = self.items.remove(index);
        Ok(Undo::ReinsertItem { index, item })
    }

    pub fn set_favorite(&mut self, id: u64, favorite: bool) -> Result<Undo, String> {
        let it = self.find_mut(id)?;
        let old = it.favorite;
        it.favorite = favorite;
        Ok(Undo::Favorite { id, old })
    }

    pub fn set_settings(&mut self, settings: Settings) -> Undo {
        Undo::Settings(std::mem::replace(&mut self.settings, settings))
    }

    /// Add recovery codes to an app/account. Validation completes before mutation.
    pub fn add_recovery_codes(&mut self, id: u64, codes: Vec<String>) -> Result<(usize, Undo), String> {
        if codes.is_empty() {
            return Err("Enter at least one recovery code.".into());
        }
        if codes.len() > 100 {
            return Err("Add no more than 100 recovery codes at a time.".into());
        }
        let mut clean: Vec<String> = Vec::with_capacity(codes.len());
        for raw in codes {
            let code = raw.trim().to_string();
            if code.is_empty() || code.chars().count() > 256 {
                return Err("Each recovery code must contain 1 to 256 characters.".into());
            }
            if clean.iter().any(|existing| existing == &code) {
                return Err("The recovery-code list contains duplicates.".into());
            }
            clean.push(code);
        }

        let current = self.find(id)?;
        if current.kind != "app" {
            return Err("Recovery codes can only be attached to an app or account.".into());
        }
        if current.recovery_codes.len() + clean.len() > 1000 {
            return Err("An account can store at most 1,000 recovery codes.".into());
        }
        if clean.iter().any(|new_code| current.recovery_codes.iter().any(|old| old.code == *new_code)) {
            return Err("One or more recovery codes already exist for this account.".into());
        }

        let old = current.clone();
        let item = self.find_mut(id)?;
        let added = clean.len();
        item.recovery_codes.extend(clean.into_iter().map(|code| RecoveryCode { code, used: false }));
        Ok((added, Undo::RestoreItem(old)))
    }

    pub fn set_recovery_code_used(&mut self, id: u64, index: usize, used: bool) -> Result<Undo, String> {
        let old = self.find(id)?.clone();
        let item = self.find_mut(id)?;
        let code = item.recovery_codes.get_mut(index)
            .ok_or_else(|| "That recovery code no longer exists.".to_string())?;
        code.used = used;
        Ok(Undo::RestoreItem(old))
    }

    pub fn delete_recovery_code(&mut self, id: u64, index: usize) -> Result<Undo, String> {
        let item = self.find_mut(id)?;
        if index >= item.recovery_codes.len() {
            return Err("That recovery code no longer exists.".into());
        }
        let code = item.recovery_codes.remove(index);
        Ok(Undo::RestoreRecoveryCode { item_id: id, index, code })
    }

    // ---- folders and files ----------------------------------------------------------------------

    fn valid_folder_name(&self, name: &str, except: Option<u64>) -> Result<String, String> {
        let name = name.trim().to_string();
        if name.is_empty() || name.chars().count() > 80 {
            return Err("A folder name must be 1 to 80 characters.".into());
        }
        if self.folders.iter().any(|f| Some(f.id) != except && f.name.eq_ignore_ascii_case(&name)) {
            return Err("A folder with that name already exists.".into());
        }
        Ok(name)
    }

    pub fn folder_views(&self) -> Vec<FolderView> {
        self.folders
            .iter()
            .map(|f| FolderView { id: f.id, name: f.name.clone(), count: self.files.iter().filter(|r| r.folder_id == f.id).count() })
            .collect()
    }

    pub fn create_folder(&mut self, name: &str) -> Result<(u64, Undo), String> {
        let name = self.valid_folder_name(name, None)?;
        let id = self.next_folder_id;
        self.next_folder_id += 1;
        self.folders.push(Folder { id, name });
        Ok((id, Undo::PopFolder { id, next_folder_id: id }))
    }

    pub fn rename_folder(&mut self, id: u64, name: &str) -> Result<Undo, String> {
        let name = self.valid_folder_name(name, Some(id))?;
        let f = self.folders.iter_mut().find(|f| f.id == id).ok_or_else(|| "That folder no longer exists.".to_string())?;
        let old = std::mem::replace(&mut f.name, name);
        Ok(Undo::RenameFolder { id, old })
    }

    /// Removes the folder and its file records. Returns the object ids to delete from disk **after the
    /// snapshot without these records has been committed**, plus the undo token.
    pub fn delete_folder(&mut self, id: u64) -> Result<(Vec<String>, Undo), String> {
        let index = self.folders.iter().position(|f| f.id == id).ok_or_else(|| "That folder no longer exists.".to_string())?;
        let folder = self.folders.remove(index);
        let mut removed: Vec<(usize, FileRecord)> = Vec::new();
        let mut kept: Vec<FileRecord> = Vec::with_capacity(self.files.len());
        for (i, f) in std::mem::take(&mut self.files).into_iter().enumerate() {
            if f.folder_id == id {
                removed.push((i, f));
            } else {
                kept.push(f);
            }
        }
        self.files = kept;
        let objects = removed.iter().map(|(_, f)| f.object_id.clone()).collect();
        Ok((objects, Undo::ReinsertFolder { index, folder, files: removed }))
    }

    pub fn has_folder(&self, id: u64) -> bool {
        self.folders.iter().any(|f| f.id == id)
    }

    pub fn find_file(&self, id: u64) -> Result<&FileRecord, String> {
        self.files.iter().find(|f| f.id == id).ok_or_else(|| "That file no longer exists.".to_string())
    }

    pub fn add_file(&mut self, mut rec: FileRecord) -> Result<(FileView, Undo), String> {
        if !self.has_folder(rec.folder_id) {
            return Err("That folder no longer exists.".into());
        }
        let id = self.next_file_id;
        rec.id = id;
        self.next_file_id += 1;
        let view = rec.view();
        self.files.push(rec);
        Ok((view, Undo::PopFile { id, next_file_id: id }))
    }

    /// Returns the object id to delete from disk **after the snapshot without this record is committed**.
    pub fn delete_file(&mut self, id: u64) -> Result<(String, Undo), String> {
        let index = self.files.iter().position(|f| f.id == id).ok_or_else(|| "That file no longer exists.".to_string())?;
        let rec = self.files.remove(index);
        Ok((rec.object_id.clone(), Undo::ReinsertFile { index, rec }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(title: &str) -> ItemInput {
        ItemInput {
            id: None,
            kind: "app".into(),
            title: title.into(),
            username: "u".into(),
            password: Some("p".into()),
            totp_secret: None,
            passkey: false,
            notes: String::new(),
        }
    }

    fn rec(folder: u64, name: &str, obj: &str) -> FileRecord {
        FileRecord { folder_id: folder, name: name.into(), mime: "application/pdf".into(), size: 10, object_id: obj.repeat(32), ..FileRecord::default() }
    }

    fn json(m: &Model) -> String {
        serde_json::to_string(m).unwrap()
    }

    #[test]
    fn create_update_keep_delete() {
        let mut m = Model::default();
        let (id, u) = m.upsert(input("GitHub")).unwrap();
        u.discard();
        assert_eq!(m.find(id).unwrap().password, "p");
        let mut edit = input("GitHub 2");
        edit.id = Some(id);
        edit.password = None; // keep
        m.upsert(edit).unwrap().1.discard();
        assert_eq!(m.find(id).unwrap().title, "GitHub 2");
        assert_eq!(m.find(id).unwrap().password, "p");
        m.delete(id).unwrap().discard();
        assert!(m.find(id).is_err());
        assert!(m.delete(id).is_err());
    }

    #[test]
    fn validation_errors_change_nothing() {
        let mut m = Model::default();
        let before = json(&m);
        assert!(m.upsert(input("  ")).is_err());
        let mut bad_kind = input("x");
        bad_kind.kind = "folder".into();
        assert!(m.upsert(bad_kind).is_err());
        let mut bad_totp = input("x");
        bad_totp.totp_secret = Some("not base32!".into());
        assert!(m.upsert(bad_totp).is_err());
        let mut missing = input("x");
        missing.id = Some(999);
        assert!(m.upsert(missing).is_err());
        assert!(m.delete(999).is_err() && m.set_favorite(999, true).is_err());
        assert!(m.create_folder("  ").is_err() && m.rename_folder(999, "x").is_err() && m.delete_folder(999).is_err());
        assert!(m.add_file(rec(999, "a", "0")).is_err() && m.delete_file(999).is_err());
        assert_eq!(json(&m), before, "a rejected operation must not modify the model");
    }

    #[test]
    fn views_never_contain_the_secret() {
        let mut m = Model::default();
        let (id, u) = m.upsert(input("x")).unwrap();
        u.discard();
        let v = serde_json::to_string(&m.find(id).unwrap().view()).unwrap();
        assert!(!v.contains("\"p\""));
        let summary = serde_json::to_string(&m.find(id).unwrap().summary()).unwrap();
        assert!(!summary.contains("password"));
    }

    #[test]
    fn recovery_codes_are_account_scoped_counted_and_undoable() {
        let mut m = Model::default();
        let (id, undo) = m.upsert(input("Discord")).unwrap();
        undo.discard();

        let (added, undo) = m.add_recovery_codes(id, vec!["alpha-code".into(), "beta-code".into()]).unwrap();
        assert_eq!(added, 2);
        undo.discard();
        let view = m.find(id).unwrap().view();
        assert_eq!(view.recovery_code_count, 2);
        assert_eq!(view.recovery_codes_remaining, 2);
        let serialized_view = serde_json::to_string(&view).unwrap();
        assert!(!serialized_view.contains("alpha-code"));
        assert!(!serialized_view.contains("beta-code"));

        let undo = m.set_recovery_code_used(id, 0, true).unwrap();
        undo.discard();
        assert_eq!(m.find(id).unwrap().view().recovery_codes_remaining, 1);

        let before_delete = json(&m);
        let undo = m.delete_recovery_code(id, 0).unwrap();
        assert_eq!(m.find(id).unwrap().recovery_codes.len(), 1);
        m.revert(undo);
        assert_eq!(json(&m), before_delete, "deletion undo restores code and original position");

        let before_invalid = json(&m);
        assert!(m.add_recovery_codes(id, vec!["beta-code".into()]).is_err(), "existing code must be rejected");
        assert!(m.add_recovery_codes(id, vec!["same".into(), "same".into()]).is_err(), "batch duplicates must be rejected");
        assert_eq!(json(&m), before_invalid, "invalid recovery-code operations must not mutate the model");

        let mut note = input("Private note");
        note.kind = "note".into();
        let (note_id, undo) = m.upsert(note).unwrap();
        undo.discard();
        assert!(m.add_recovery_codes(note_id, vec!["not-allowed".into()]).is_err());
    }

    #[test]
    fn folders_and_files() {
        let mut m = Model::default();
        assert_eq!(m.folders.len(), 4);
        let (f, _) = m.create_folder("Taxes").unwrap();
        assert!(m.create_folder("taxes").is_err(), "duplicate names are refused case-insensitively");
        m.rename_folder(f, "Taxes 2026").unwrap();
        let (view, _) = m.add_file(rec(f, "a.pdf", "0")).unwrap();
        assert!(!view.previewable);
        assert_eq!(m.folder_views().iter().find(|v| v.id == f).unwrap().count, 1);
        let (objects, _) = m.delete_folder(f).unwrap();
        assert_eq!(objects, vec!["0".repeat(32)]);
        assert!(m.files.is_empty());
    }

    /// Every mutation followed by its undo must restore the model byte-for-byte (compared as JSON).
    #[test]
    fn every_mutation_is_exactly_undoable() {
        let mut m = Model::default();
        let (a, _) = m.upsert(input("A")).unwrap();
        let (b, _) = m.upsert(input("B")).unwrap();
        let (c, _) = m.upsert(input("C")).unwrap();
        let (fx, _) = m.create_folder("X").unwrap();
        let (fy, _) = m.create_folder("Y").unwrap();
        for (folder, name, obj) in [(fx, "1", "1"), (fy, "2", "2"), (fx, "3", "3"), (fy, "4", "4"), (fx, "5", "5")] {
            m.add_file(rec(folder, name, obj)).unwrap();
        }
        let base = json(&m);

        let (_, u) = m.upsert(input("NEW")).unwrap();
        assert_ne!(json(&m), base);
        m.revert(u);
        assert_eq!(json(&m), base, "create item");

        let mut edit = input("EDITED");
        edit.id = Some(b);
        edit.password = Some("changed".into());
        edit.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
        let (_, u) = m.upsert(edit).unwrap();
        m.revert(u);
        assert_eq!(json(&m), base, "edit item");

        for id in [a, b, c] {
            let u = m.delete(id).unwrap();
            assert_ne!(json(&m), base);
            m.revert(u);
            assert_eq!(json(&m), base, "delete item {id}");
        }
        let u = m.set_favorite(b, true).unwrap();
        m.revert(u);
        assert_eq!(json(&m), base, "favorite");
        let u = m.set_settings(Settings { auto_lock_secs: 0, clipboard_clear_secs: 90 });
        m.revert(u);
        assert_eq!(json(&m), base, "settings");

        let (_, u) = m.create_folder("Z").unwrap();
        m.revert(u);
        assert_eq!(json(&m), base, "create folder");
        let u = m.rename_folder(fx, "Renamed").unwrap();
        m.revert(u);
        assert_eq!(json(&m), base, "rename folder");

        // Deleting a middle folder interleaved with other folders' files must restore the exact order.
        for folder in [fx, fy, 1, 2] {
            let (objects, u) = m.delete_folder(folder).unwrap();
            assert_eq!(objects.len(), m.files.len().abs_diff(5), "{folder}");
            m.revert(u);
            assert_eq!(json(&m), base, "delete folder {folder}");
        }
        let (_, u) = m.add_file(rec(fx, "new", "9")).unwrap();
        m.revert(u);
        assert_eq!(json(&m), base, "add file");
        for file_id in 1..=5 {
            let (_, u) = m.delete_file(file_id).unwrap();
            m.revert(u);
            assert_eq!(json(&m), base, "delete file {file_id}");
        }
    }

    #[test]
    fn mime_guessing_and_preview_rules() {
        assert_eq!(guess_mime("Photo.JPG"), "image/jpeg");
        assert_eq!(guess_mime("noext"), "application/octet-stream");
        let mut r = FileRecord { mime: "image/png".into(), size: 100, ..FileRecord::default() };
        assert!(r.view().previewable);
        r.size = PREVIEW_MAX_BYTES + 1;
        assert!(!r.view().previewable);
        r.mime = "image/svg+xml".into();
        r.size = 1;
        assert!(!r.view().previewable, "SVG is never previewed inline");
    }

    #[test]
    fn old_vaults_without_folders_still_load() {
        let m: Model = serde_json::from_str(r#"{"schema":1,"next_id":5,"items":[]}"#).unwrap();
        assert_eq!(m.next_id, 5);
        assert_eq!(m.folders.len(), 4);
        assert_eq!(m.next_folder_id, 5);
    }

    #[test]
    fn forward_compatible_deserialization() {
        let m: Model = serde_json::from_str(r#"{"schema":1,"next_id":3,"unknown_future_field":true}"#).unwrap();
        assert_eq!(m.next_id, 3);
        assert_eq!(m.settings.auto_lock_secs, 300);
    }
}
