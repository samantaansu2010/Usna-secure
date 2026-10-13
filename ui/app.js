// USNA Secure UI. Holds NO keys. Every piece of data comes from the Rust command API; the only
// secrets this file ever sees are what the user types and what they explicitly reveal.
(() => {
  'use strict';
  const tauri = window.__TAURI__;
  if (!tauri) { document.body.textContent = 'This interface must run inside the USNA Secure desktop app.'; return; }
  const invoke = tauri.core.invoke;
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const COLORS = ['#ffb454', '#3fb8a8', '#8fb7ff', '#ff8f7a', '#c3a6ff', '#7bd88f'];
  const NAV = [['all', '◫', 'All'], ['app', '⌘', 'Apps'], ['folder', '▤', 'Folders'], ['fav', '★', 'Favorites'], ['note', '✎', 'Secure notes'], ['set', '⚙', 'Settings']];
  const EMPTY = '<div class="empty">Select an item to see its fields.</div>';
  const S = { items: [], searchResults: null, searchSeq: 0, view: 'all', sel: null, detail: null, shown: null, recoveryCodes: null,
    settings: { auto_lock_secs: 300, clipboard_clear_secs: 20 }, totpTimer: null, busy: false,
    folders: [], folder: null, files: [], file: null, preview: null, verify: null, nameMode: null };

  // ---- helpers --------------------------------------------------------------------------------
  let toastTimer = 0;
  function toast(msg) { const t = $('toast'); t.textContent = msg; t.classList.add('on'); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('on'), 2600); }
  const errText = (e) => (typeof e === 'string' ? e : (e && e.message) || 'Something went wrong.');
  function screen(name) { for (const id of ['setup', 'lock', 'app']) $(id).hidden = id !== name; }
  function applyTheme(theme, persist = true) {
    const selected = theme === 'light' ? 'light' : 'dark';
    document.documentElement.dataset.theme = selected;
    try {
      if (persist) localStorage.setItem('usna-secure-theme', selected);
    } catch (_) { /* Theme persistence is optional; vault data never uses browser storage. */ }
  }
  function strength(p, barId) {
    let s = 0; if (p.length >= 12) s++; if (p.length >= 16) s++; if (/[a-z]/.test(p) && /[A-Z]/.test(p)) s++; if (/\d/.test(p)) s++; if (/[^A-Za-z0-9 ]/.test(p) || p.split(' ').length >= 4) s++;
    s = p ? Math.min(s, 4) : 0; const b = $(barId); b.style.width = (s * 25) + '%'; b.style.background = ['var(--bad)', 'var(--bad)', 'var(--ac)', 'var(--ok)', 'var(--ok)'][s];
  }
  async function guarded(fn) { try { await fn(); } catch (e) { toast(errText(e)); } }

  // ---- screens and state --------------------------------------------------------------------
  async function boot() {
    try {
      let savedTheme = null;
      try { savedTheme = localStorage.getItem('usna-secure-theme'); } catch (_) { /* optional */ }
      applyTheme(savedTheme || (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'), false);
      const st = await invoke('vault_status');
      if (!st.exists) { screen('setup'); $('spw').focus(); }
      else if (!st.unlocked) { screen('lock'); $('pw').focus(); }
      else await enter();
    } catch (e) { screen('lock'); $('lerr').textContent = errText(e); }
  }
  async function enter() { screen('app'); S.view = 'all'; S.settings = await invoke('get_settings'); await refresh(); renderDetail(); }
  function resetUi(message) {
    S.items = []; S.searchResults = []; S.searchSeq++; S.sel = null; S.detail = null; S.shown = null; S.recoveryCodes = null;
    S.folders = []; S.folder = null; S.files = []; S.file = null; S.preview = null; S.verify = null;
    $('content').innerHTML = ''; $('detail').innerHTML = EMPTY; $('q').value = '';
    for (const id of ['dlg', 'pwdlg', 'namedlg', 'recoverydlg']) { const d = $(id); if (d && d.open) d.close(); }
    for (const id of ['fp', 'fo', 'cp0', 'cp1', 'cp2', 'pw', 'spw', 'spw2', 'recoveryInput']) $(id).value = '';
    $('fp').type = 'password'; $('fpToggle').textContent = 'Show';
    $('fo').type = 'password'; $('foToggle').textContent = 'Show';
    $('lockMsg').textContent = message || 'Your vault is locked.'; $('lerr').textContent = '';
    screen('lock'); $('pw').focus();
  }
  async function refresh() {
    S.items = await invoke('list_items');
    await performSearch(false);
    if (S.sel !== null && !S.items.some((i) => i.id === S.sel)) { S.sel = null; S.detail = null; S.shown = null; S.recoveryCodes = null; }
    S.folders = await invoke('list_folders');
    if (S.folder !== null) {
      if (!S.folders.some((f) => f.id === S.folder)) { S.folder = null; S.files = []; S.file = null; S.preview = null; }
      else {
        S.files = await invoke('list_files', { folderId: S.folder });
        if (S.file && !S.files.some((f) => f.id === S.file.id)) { S.file = null; S.preview = null; }
      }
    }
    render();
    if (S.sel !== null) { S.detail = await invoke('get_item', { id: S.sel }); renderDetail(); }
  }

  // ---- rendering --------------------------------------------------------------------------------
  function render() {
    $('nav').innerHTML = NAV.map(([k, i, l]) => `<button class="nl ${S.view === k ? 'on' : ''}" data-act="nav" data-view="${k}"><span>${i}</span><span>${l}</span></button>`).join('');
    const v = S.view; $('title').textContent = NAV.find((n) => n[0] === v)[2];
    const subtitles = {
      all: 'Your accounts and private notes, in one place.',
      app: 'Sign-in details for your apps and online accounts.',
      folder: S.folder === null ? 'Organize encrypted files into private folders.' : 'Encrypted files stored in this folder.',
      fav: 'The accounts and notes you reach for most.',
      note: 'Private text kept inside the encrypted vault.',
      set: 'Security, appearance, and vault maintenance.'
    };
    $('subtitle').textContent = subtitles[v] || subtitles.all;
    $('q').hidden = v === 'set';
    if (v === 'set') { $('content').innerHTML = settingsHtml(); return; }
    const source = S.searchResults || S.items;
    const list = source.filter((x) => (v === 'all' || v === 'folder' || (v === 'fav' ? x.favorite : x.kind === v)));
    const card = (x) => `<button class="card ${S.sel === x.id ? 'sel' : ''}" data-act="open" data-id="${x.id}"><div class="ico" style="background:${COLORS[x.id % 6]}">${esc(x.title[0] || '?')}</div>${x.favorite ? '<span class="fav">★</span>' : ''}<b>${esc(x.title)}</b><small>${esc(x.subtitle || ' ')}</small></button>`;
    const folders = foldersGrid();
    let h = '';
    if (v !== 'folder') {
      h += list.length ? `<div class="grid">${list.map(card).join('')}</div>`
        : `<div class="empty"><strong>${S.items.length ? 'No matching items' : 'Your vault is empty'}</strong><span>${S.items.length ? 'Try another name, username, or phrase from the notes.' : 'Choose New item to add your first app or note.'}</span></div>`;
    }
    if (v === 'all') h = (list.length ? '<div class="sec">Apps and notes</div>' : '') + h + '<div class="sec">Folders</div>' + folders;
    if (v === 'folder') h = S.folder === null ? `<div class="row end" style="margin:0 0 14px"><button class="btn pri" data-act="newFolder">New folder</button></div>${folders}` : folderPage();
    $('content').innerHTML = h;
  }
  const fmtSize = (n) => (n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : n < 1073741824 ? (n / 1048576).toFixed(1) + ' MB' : (n / 1073741824).toFixed(2) + ' GB');
  function foldersGrid() {
    return `<div class="grid">${S.folders.map((f) => `<button class="card" data-act="openFolder" data-id="${f.id}"><div class="ico" style="background:var(--ac2)">▤</div><b>${esc(f.name)}</b><small>${f.count} file${f.count === 1 ? '' : 's'}</small></button>`).join('')}</div>`;
  }
  function folderPage() {
    const f = S.folders.find((x) => x.id === S.folder); if (!f) return '';
    const files = S.files.length
      ? `<div class="grid">${S.files.map((x) => `<button class="card ${S.file && S.file.id === x.id ? 'sel' : ''}" data-act="openFile" data-id="${x.id}"><div class="ico" style="background:${COLORS[x.id % 6]}">${x.mime.startsWith('image/') ? '▣' : x.mime.startsWith('video/') ? '▶' : '▤'}</div><b>${esc(x.name)}</b><small>${fmtSize(x.size)}</small></button>`).join('')}</div>`
      : '<div class="empty" style="height:180px">This folder is empty. Choose Import file to encrypt a file into it.</div>';
    return `<div class="row" style="margin:0 0 16px;flex-wrap:wrap"><button class="btn" data-act="backFolders">← All folders</button><b style="flex:1;font-size:18px">${esc(f.name)}</b><button class="btn pri" data-act="importFile">Import file</button><button class="btn" data-act="renameFolder">Rename</button><button class="btn" data-act="deleteFolder" style="color:var(--bad)">Delete folder</button></div>${files}`;
  }
  function verifyHtml() {
    const r = S.verify; if (!r) return '';
    const head = r.ok ? `<span class="badge">Healthy</span> ${r.files_checked} encrypted file(s) verified.` : `<b style="color:var(--bad)">Problems found</b> (${r.files_checked} file(s) checked)`;
    return `<div style="margin-top:10px">${head}${r.problems.length ? '<ul>' + r.problems.map((p) => `<li>${esc(p)}</li>`).join('') + '</ul>' : ''}</div>`;
  }
  function settingsHtml() {
    const opt = (cur, arr) => arr.map(([n, l]) => `<option value="${n}" ${cur === n ? 'selected' : ''}>${l}</option>`).join('');
    return `<div class="sec">Session security</div>
    <div class="f"><label>Lock after inactivity</label><select class="in" style="margin:0" data-set="auto_lock_secs">${opt(S.settings.auto_lock_secs, [[60, '1 minute'], [300, '5 minutes'], [900, '15 minutes'], [0, 'Never']])}</select><div class="note">The vault locks in Rust after this period without activity.</div></div>
    <div class="f"><label>Clear clipboard after</label><select class="in" style="margin:0" data-set="clipboard_clear_secs">${opt(S.settings.clipboard_clear_secs, [[10, '10 seconds'], [20, '20 seconds'], [45, '45 seconds'], [90, '90 seconds']])}</select><div class="note">Copied secrets are cleared only if the clipboard still contains the value USNA Secure copied.</div></div>
    <div class="f"><label>Master password</label><button class="btn" data-act="openPw">Change master password</button><div class="note">Old copies and exports of the vault may still accept the old password.</div></div>
    <div class="sec">Appearance</div>
    <div class="f"><label>Theme</label><div class="row"><button class="btn" data-act="theme" data-theme="light">Light</button><button class="btn" data-act="theme" data-theme="dark">Dark</button></div><div class="note">Saved as a local display preference, not inside the vault.</div></div>
    <div class="sec">Account data</div>
    <div class="f"><label>Import or export account records</label><div class="row" style="flex-wrap:wrap"><button class="btn" data-act="exportAccounts">Export JSON</button><button class="btn" data-act="importAccounts">Import JSON</button></div><div class="note">JSON exports are plaintext and include account secrets, notes, authenticator seeds, and recovery codes. Only use them temporarily and store them safely.</div></div>
    <div class="sec">Vault maintenance</div>
    <div class="f"><label>Integrity</label><button class="btn" data-act="verify">Check vault integrity</button>${verifyHtml()}</div>
    <div class="f"><label>Shortcuts</label><div><b class="mono">Ctrl + K</b> Search the vault</div><div><b class="mono">Ctrl + L</b> Lock immediately</div></div>`;
  }
  function renderDetail() {
    const d = $('detail'), x = S.detail;
    clearInterval(S.totpTimer);
    if (S.file) {
      const f = S.file; d.classList.remove('none');
      d.innerHTML = `<div class="dh"><div class="ico" style="background:${COLORS[f.id % 6]}">▤</div><h2>${esc(f.name)}</h2><button class="btn sm x" data-act="closeFile" aria-label="Close details">✕</button></div>
        <div class="f"><label>Type and size</label>${esc(f.mime)} · ${fmtSize(f.size)}</div>
        ${S.preview ? `<div class="f"><img alt="Preview of ${esc(f.name)}" src="${S.preview}" style="max-width:100%;border-radius:10px;display:block"></div>` : ''}
        <div class="row" style="margin-top:16px;flex-wrap:wrap">${f.previewable ? '<button class="btn" data-act="previewFile">Preview</button>' : ''}<button class="btn" data-act="exportFile">Export</button><button class="btn" data-act="deleteFile" style="color:var(--bad)">Delete</button></div>
        <div class="note">Stored encrypted. Export saves an unencrypted copy where you choose.</div>`;
      return;
    }
    if (!x) { d.innerHTML = EMPTY; d.classList.add('none'); return; }
    d.classList.remove('none');
    const fld = (l, v, extra = '') => `<div class="f"><label>${l}</label><div class="fr"><span>${v}</span>${extra}</div></div>`;
    let h = `<div class="dh"><div class="ico" style="background:${COLORS[x.id % 6]}">${esc(x.title[0] || '?')}</div><h2>${esc(x.title)}</h2><button class="btn sm x" data-act="close" aria-label="Close details">✕</button></div>`;
    if (x.username) h += fld('Email or username', esc(x.username), '<button class="btn sm" data-act="copy" data-field="username">Copy</button>');
    if (x.has_password) {
      const shown = S.shown !== null;
      h += `<div class="f"><label>Password</label><div class="fr"><span class="mono">${shown ? esc(S.shown) : '•'.repeat(Math.min(x.password_len, 16))}</span><button class="btn sm" data-act="${shown ? 'hide' : 'reveal'}">${shown ? 'Hide' : 'Show'}</button><button class="btn sm" data-act="copy" data-field="password">Copy</button></div></div>`;
    }
    if (x.has_totp) h += `<div class="f"><label>Authenticator</label><div class="totp"><div class="ring"><svg width="74" height="74"><circle cx="37" cy="37" r="32" fill="none" stroke="var(--line)" stroke-width="5"/><circle id="rg" cx="37" cy="37" r="32" fill="none" stroke="var(--ac)" stroke-width="5" stroke-linecap="round" stroke-dasharray="201" stroke-dashoffset="0"/></svg><div class="n" id="rn"></div></div><div><div class="code" id="cd">······</div><button class="btn sm" data-act="copy" data-field="totp">Copy code</button></div></div></div>`;
    if (x.kind === 'app') h += fld('Passkey', x.passkey ? '<span class="badge">Recorded</span>' : '<span style="color:var(--mut)">None recorded</span>');
    if (x.notes) h += fld('Notes', esc(x.notes).replace(/\n/g, '<br>'));
    if (x.kind === 'app') {
      const total = Number(x.recovery_code_count || 0);
      const remaining = Number(x.recovery_codes_remaining || 0);
      h += `<div class="section-heading"><div><h3>Recovery codes</h3><small>${remaining} remaining of ${total}</small></div><button class="btn sm" data-act="addRecoveryCodes">＋ Add</button></div>`;
      if (S.recoveryCodes === null) {
        h += total
          ? `<div class="f"><div style="color:var(--mut);font-size:12px;margin-bottom:10px">Code values stay concealed until you choose to reveal them.</div><button class="btn" data-act="showRecoveryCodes">View recovery codes</button></div>`
          : `<div class="f"><div style="color:var(--mut);font-size:12px">No recovery codes are stored for this account.</div></div>`;
      } else {
        h += S.recoveryCodes.length
          ? `<div class="recovery-list">${S.recoveryCodes.map((row) => `<div class="recovery-row ${row.used ? 'is-used' : ''}"><span class="recovery-code">${esc(row.code)}</span><div class="recovery-row-actions">${row.used ? '<span class="used-label">Used</span>' : ''}<button class="btn sm" data-act="copyRecovery" data-index="${row.index}" aria-label="Copy recovery code">Copy</button><button class="btn sm" data-act="toggleRecovery" data-index="${row.index}">${row.used ? 'Undo' : 'Used'}</button><button class="btn sm danger" data-act="deleteRecovery" data-index="${row.index}" aria-label="Remove recovery code">×</button></div></div>`).join('')}</div><div class="row end"><button class="btn sm" data-act="hideRecoveryCodes">Hide codes</button></div>`
          : `<div class="f"><div style="color:var(--mut);font-size:12px">No recovery codes are stored for this account.</div><button class="btn sm" data-act="hideRecoveryCodes">Hide codes</button></div>`;
      }
    }
    h += `<div class="detail-actions"><button class="btn" data-act="edit">Edit</button><button class="btn" data-act="fav">${x.favorite ? 'Remove favorite' : 'Add favorite'}</button><button class="btn danger" data-act="del">Delete</button></div>`;
    d.innerHTML = h;
    if (x.has_totp) { tick(); S.totpTimer = setInterval(tick, 1000); }
  }
  async function tick() {
    const x = S.detail; if (!x || !x.has_totp || !$('cd')) return;
    try {
      const t = await invoke('totp_now', { id: x.id }); if (!$('cd')) return;
      $('cd').textContent = t.code.slice(0, 3) + ' ' + t.code.slice(3); $('rn').textContent = t.remaining + 's';
      $('rg').style.strokeDashoffset = String(201 * (1 - t.remaining / 30)); $('rg').style.stroke = t.remaining <= 5 ? 'var(--bad)' : 'var(--ac)';
    } catch (_) { /* vault locked meanwhile; the vault-locked event resets the UI */ }
  }

  // ---- actions (single delegated listener: the CSP forbids inline handlers) ---------------------------
  const A = {
    async nav(d) { S.view = d.view; render(); },
    async open(d) { S.file = null; S.preview = null; S.sel = Number(d.id); S.shown = null; S.recoveryCodes = null; S.detail = await invoke('get_item', { id: S.sel }); render(); renderDetail(); },
    async close() { S.sel = null; S.detail = null; S.shown = null; S.recoveryCodes = null; render(); renderDetail(); },
    async reveal() { S.shown = await invoke('reveal_password', { id: S.sel }); renderDetail(); },
    async hide() { S.shown = null; renderDetail(); },
    async copy(d) { await invoke('copy_field', { id: S.sel, field: d.field }); toast(`Copied. The clipboard clears in ${S.settings.clipboard_clear_secs} seconds if unchanged.`); },
    async fav() { await invoke('set_favorite', { id: S.sel, favorite: !S.detail.favorite }); await refresh(); toast('Favorites updated'); },
    async del() { if (!confirm(`Delete "${S.detail.title}" from the vault? This cannot be undone.`)) return; await invoke('delete_item', { id: S.sel }); S.sel = null; S.detail = null; S.shown = null; S.recoveryCodes = null; await refresh(); renderDetail(); toast('Deleted'); },
    async lock() { await invoke('vault_lock'); resetUi('Your vault is locked.'); },
    async theme(d) { applyTheme(d.theme); },
    async newItem() { openItemDialog(null); },
    async edit() { openItemDialog(S.detail); },
    async gen() { $('fp').value = await invoke('generate_password', { length: 20 }); $('fp').type = 'password'; $('fpToggle').textContent = 'Show'; strength($('fp').value, 'fbar'); },
    async togglePasswordInput() {
      const field = $('fp');
      field.type = field.type === 'password' ? 'text' : 'password';
      $('fpToggle').textContent = field.type === 'password' ? 'Show' : 'Hide';
      field.focus();
    },
    async toggleTotpInput() {
      const field = $('fo');
      field.type = field.type === 'password' ? 'text' : 'password';
      $('foToggle').textContent = field.type === 'password' ? 'Show' : 'Hide';
      field.focus();
    },
    async closeDlg() { $('dlg').close(); },
    async openPw() { $('perr').textContent = ''; $('pwdlg').showModal(); $('cp0').focus(); },
    async closePw() { $('pwdlg').close(); },
    async openFolder(d) { S.folder = Number(d.id); S.view = 'folder'; S.file = null; S.preview = null; S.sel = null; S.detail = null; S.recoveryCodes = null; S.files = await invoke('list_files', { folderId: S.folder }); render(); renderDetail(); },
    async backFolders() { S.folder = null; S.files = []; S.file = null; S.preview = null; S.recoveryCodes = null; render(); renderDetail(); },
    async newFolder() { S.nameMode = 'new'; $('nameTitle').textContent = 'New folder'; $('nm').value = ''; $('nerr').textContent = ''; $('namedlg').showModal(); $('nm').focus(); },
    async renameFolder() { const f = S.folders.find((x) => x.id === S.folder); S.nameMode = 'rename'; $('nameTitle').textContent = 'Rename folder'; $('nm').value = f ? f.name : ''; $('nerr').textContent = ''; $('namedlg').showModal(); $('nm').select(); },
    async closeName() { $('namedlg').close(); },
    async deleteFolder() {
      const f = S.folders.find((x) => x.id === S.folder); if (!f) return;
      if (!confirm(`Delete the folder "${f.name}" and its ${f.count} encrypted file(s)? This cannot be undone.`)) return;
      await invoke('delete_folder', { id: S.folder }); S.folder = null; S.files = []; S.file = null; S.preview = null; await refresh(); renderDetail(); toast('Folder deleted');
    },
    async importFile() { const v = await invoke('import_file', { folderId: S.folder }); if (v) { toast('Encrypted and added to the folder'); await refresh(); } },
    async openFile(d) { S.file = S.files.find((x) => x.id === Number(d.id)) || null; S.preview = null; S.sel = null; S.detail = null; S.recoveryCodes = null; render(); renderDetail(); },
    async closeFile() { S.file = null; S.preview = null; render(); renderDetail(); },
    async previewFile() { S.preview = await invoke('preview_file', { id: S.file.id }); renderDetail(); },
    async exportFile() { if (!confirm('This saves an UNENCRYPTED copy of the file where you choose. Continue?')) return; if (await invoke('export_file', { id: S.file.id })) toast('Exported'); },
    async deleteFile() { if (!confirm(`Delete "${S.file.name}" from the vault? This cannot be undone.`)) return; await invoke('delete_file', { id: S.file.id }); S.file = null; S.preview = null; await refresh(); renderDetail(); toast('Deleted'); },
    async verify() { toast('Checking every encrypted file…'); S.verify = await invoke('verify_vault'); render(); },
    async exportAccounts() {
      const confirmed = confirm('This creates a PLAIN TEXT JSON file containing account names, usernames, passwords, notes, authenticator seeds and recovery codes. The file is not encrypted. Store it securely and delete it when finished. Continue?');
      if (!confirmed) return;
      const saved = await invoke('export_accounts');
      if (saved) toast('Plaintext export saved. Protect the file and remove it when no longer needed.');
    },
    async importAccounts() {
      const confirmed = confirm('Import a USNA Secure account JSON export? Its contents are plaintext. Existing entries will not be overwritten; imported entries are added as new records. Only import a file you trust.');
      if (!confirmed) return;
      const count = await invoke('import_accounts');
      if (!count) return;
      await refresh();
      renderDetail();
      toast(`Imported ${count} account record${count === 1 ? '' : 's'}`);
    },
    async showRecoveryCodes() { S.recoveryCodes = await invoke('get_recovery_codes', { id: S.sel }); renderDetail(); },
    async hideRecoveryCodes() { S.recoveryCodes = null; renderDetail(); },
    async addRecoveryCodes() {
      $('recoveryInput').value = ''; $('recoveryErr').textContent = '';
      $('recoverydlg').showModal(); $('recoveryInput').focus();
    },
    async closeRecoveryDlg() {
      $('recoveryInput').value = ''; $('recoveryErr').textContent = '';
      $('recoverydlg').close();
    },
    async copyRecovery(d) {
      await invoke('copy_field', { id: S.sel, field: 'recovery:' + Number(d.index) });
      toast(`Copied. The clipboard clears in ${S.settings.clipboard_clear_secs} seconds if unchanged.`);
    },
    async toggleRecovery(d) {
      const index = Number(d.index);
      const current = S.recoveryCodes && S.recoveryCodes.find((row) => row.index === index);
      if (!current) return;
      await invoke('set_recovery_code_used', { id: S.sel, index, used: !current.used });
      S.recoveryCodes = null;
      await refresh();
      S.recoveryCodes = await invoke('get_recovery_codes', { id: S.sel });
      renderDetail();
      toast(current.used ? 'Recovery code marked unused' : 'Recovery code marked used');
    },
    async deleteRecovery(d) {
      const index = Number(d.index);
      if (!confirm('Remove this recovery code from the vault? This cannot be undone.')) return;
      const keepOpen = S.recoveryCodes !== null;
      await invoke('delete_recovery_code', { id: S.sel, index });
      S.recoveryCodes = null;
      await refresh();
      if (keepOpen && S.sel !== null) S.recoveryCodes = await invoke('get_recovery_codes', { id: S.sel });
      renderDetail();
      toast('Recovery code removed');
    },
  };
  document.addEventListener('click', (e) => { const el = e.target.closest('[data-act]'); if (!el || !A[el.dataset.act]) return; guarded(() => A[el.dataset.act](el.dataset)); });
  document.addEventListener('change', (e) => {
    const key = e.target.dataset && e.target.dataset.set; if (!key) return;
    guarded(async () => { S.settings = { ...S.settings, [key]: Number(e.target.value) }; await invoke('set_settings', { settings: S.settings }); toast('Setting saved'); });
  });
  let searchDebounce = 0;
  async function performSearch(shouldRender = true) {
    const seq = ++S.searchSeq;
    try {
      const results = await invoke('search_items', { query: $('q').value.trim() });
      if (seq !== S.searchSeq) return;
      S.searchResults = results;
      if (shouldRender) render();
    } catch (err) {
      if (seq !== S.searchSeq) return;
      S.searchResults = $('q').value.trim() ? [] : S.items;
      if (shouldRender) render();
      toast(errText(err));
    }
  }
  $('q').addEventListener('input', () => {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(() => { guarded(() => performSearch(true)); }, 140);
  });
  $('spw').addEventListener('input', () => strength($('spw').value, 'sbar'));
  $('fp').addEventListener('input', () => strength($('fp').value, 'fbar'));
  $('fk').addEventListener('change', () => { $('appFields').hidden = $('fk').value === 'note'; });

  function openItemDialog(item) {
    S.recoveryCodes = null; S.shown = null;
    renderDetail(); // Remove previously revealed values from the detail DOM before editing.
    $('dlgTitle').textContent = item ? 'Edit item' : 'New item'; $('itemForm').dataset.id = item ? String(item.id) : '';
    $('fk').value = item ? item.kind : 'app'; $('fk').disabled = !!item; $('appFields').hidden = $('fk').value === 'note';
    $('ft').value = item ? item.title : ''; $('fu').value = item ? item.username : '';
    $('fp').value = ''; $('fp').type = 'password'; $('fpToggle').textContent = 'Show'; $('fp').placeholder = item && item.has_password ? 'Leave blank to keep the current password' : '';
    $('fo').value = ''; $('fo').type = 'password'; $('foToggle').textContent = 'Show'; $('fo').placeholder = item && item.has_totp ? 'Leave blank to keep the current secret' : 'JBSW Y3DP EHPK 3PXP';
    $('fa').checked = item ? item.passkey : false; $('fn').value = item ? item.notes : ''; $('ferr').textContent = ''; strength('', 'fbar');
    $('dlg').showModal(); $('ft').focus();
  }
  $('itemForm').addEventListener('submit', (e) => {
    e.preventDefault();
    guarded(async () => {
      const id = $('itemForm').dataset.id; const note = $('fk').value === 'note';
      const input = { id: id ? Number(id) : null, kind: $('fk').value, title: $('ft').value, username: note ? '' : $('fu').value,
        password: note || !$('fp').value ? null : $('fp').value, totp_secret: note || !$('fo').value.trim() ? null : $('fo').value.trim(), passkey: note ? false : $('fa').checked, notes: $('fn').value };
      try { S.sel = await invoke('save_item', { input }); } catch (err) { $('ferr').textContent = errText(err); return; }
      $('fp').value = ''; $('fo').value = ''; $('dlg').close(); S.shown = null; await refresh(); renderDetail(); toast('Saved');
    });
  });
  $('setupForm').addEventListener('submit', (e) => {
    e.preventDefault(); if (S.busy) return;
    const p = $('spw').value; $('serr').textContent = '';
    if (p !== $('spw2').value) { $('serr').textContent = 'The two passwords do not match.'; return; }
    S.busy = true; $('sbtn').disabled = true; $('sbtn').textContent = 'Creating vault…';
    invoke('vault_create', { password: p }).then(() => { $('spw').value = ''; $('spw2').value = ''; return enter(); })
      .catch((err) => { $('serr').textContent = errText(err); })
      .finally(() => { S.busy = false; $('sbtn').disabled = false; $('sbtn').textContent = 'Create vault'; });
  });
  $('lockForm').addEventListener('submit', (e) => {
    e.preventDefault(); if (S.busy) return;
    const p = $('pw').value; $('lerr').textContent = '';
    if (!p) { $('lerr').textContent = 'Enter your master password to unlock.'; return; }
    S.busy = true; $('lbtn').disabled = true; $('lbtn').textContent = 'Unlocking…';
    invoke('vault_unlock', { password: p }).then(() => { $('pw').value = ''; return enter(); })
      .catch((err) => { $('lerr').textContent = errText(err); $('pw').select(); })
      .finally(() => { S.busy = false; $('lbtn').disabled = false; $('lbtn').textContent = 'Unlock vault'; });
  });
  $('nameForm').addEventListener('submit', (e) => {
    e.preventDefault();
    guarded(async () => {
      try {
        if (S.nameMode === 'rename') await invoke('rename_folder', { id: S.folder, name: $('nm').value });
        else await invoke('create_folder', { name: $('nm').value });
      } catch (err) { $('nerr').textContent = errText(err); return; }
      $('namedlg').close(); await refresh(); toast('Saved');
    });
  });
  $('recoveryForm').addEventListener('submit', (e) => {
    e.preventDefault();
    guarded(async () => {
      const codes = $('recoveryInput').value.split(/\r?\n/).map((code) => code.trim()).filter(Boolean);
      $('recoveryErr').textContent = '';
      if (!codes.length) { $('recoveryErr').textContent = 'Enter at least one recovery code.'; return; }
      const keepOpen = S.recoveryCodes !== null;
      try {
        const added = await invoke('add_recovery_codes', { id: S.sel, codes });
        $('recoveryInput').value = ''; $('recoverydlg').close();
        S.recoveryCodes = null;
        await refresh();
        if (keepOpen && S.sel !== null) S.recoveryCodes = await invoke('get_recovery_codes', { id: S.sel });
        renderDetail();
        toast(`${added} recovery code${added === 1 ? '' : 's'} saved`);
      } catch (err) {
        $('recoveryErr').textContent = errText(err);
      }
    });
  });
  $('pwForm').addEventListener('submit', (e) => {
    e.preventDefault(); $('perr').textContent = '';
    if ($('cp1').value !== $('cp2').value) { $('perr').textContent = 'The new passwords do not match.'; return; }
    invoke('change_password', { current: $('cp0').value, new: $('cp1').value })
      .then(() => { for (const id of ['cp0', 'cp1', 'cp2']) $(id).value = ''; $('pwdlg').close(); toast('Master password changed'); })
      .catch((err) => { $('perr').textContent = errText(err); });
  });

  // Ctrl+L locks; user activity keeps the Rust inactivity timer alive (throttled).
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key.toLowerCase() === 'l' && !$('app').hidden) {
      e.preventDefault(); A.lock().catch(() => {});
    } else if (e.ctrlKey && e.key.toLowerCase() === 'k' && !$('app').hidden) {
      e.preventDefault();
      if (S.view === 'set') { S.view = 'all'; render(); }
      $('q').focus(); $('q').select();
    } else if (e.key === 'Escape' && $('recoverydlg').open) {
      $('recoveryInput').value = '';
    }
  });
  let lastTouch = 0;
  const touch = () => { const n = Date.now(); if (!$('app').hidden && n - lastTouch > 5000) { lastTouch = n; invoke('touch').catch(() => {}); } };
  for (const ev of ['mousemove', 'keydown', 'click']) document.addEventListener(ev, touch, { passive: true });
  tauri.event.listen('vault-locked', () => resetUi('Locked after inactivity.'));
  boot();
})();
