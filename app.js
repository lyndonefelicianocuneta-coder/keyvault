/* =========================================================
   KEYVAULT — local-first encrypted credential vault
   ---------------------------------------------------------
   • Key derivation : PBKDF2 / SHA-256, 600,000 iterations, 16-byte random salt
   • Encryption     : AES-256-GCM, fresh 12-byte random IV on every save
   • Storage        : IndexedDB holds ONLY the encrypted blob + KDF params
   • The master password and derived key live in memory only while unlocked.
   • Nothing is ever sent over the network (CSP: connect-src 'none').
   • ID photos: each image is encrypted separately (same key, own IV) in a
     second IndexedDB store; only encrypted bytes are ever written.
   • Passwords are never written to the console.
   ========================================================= */
'use strict';

(() => {
  // ---------- Settings ----------
  const DB_NAME = 'keyvault';
  const STORE = 'vault';
  const RECORD_KEY = 'main';
  const KDF_ITERATIONS = 600000;
  const MIN_ITER = 100000;          // refuse weaker backups
  const MAX_ITER = 5000000;         // refuse absurd values (DoS)
  const MIN_MASTER_LEN = 10;
  const AUTO_LOCK_MS = 5 * 60 * 1000;
  const REVEAL_MS = 15 * 1000;
  const CLIPBOARD_CLEAR_MS = 30 * 1000;
  const CATEGORIES = ['Work', 'Personal', 'Banking', 'Social Media', 'Shopping', 'Applications', 'Other'];
  const FILES = 'files';
  const ID_TYPES = ['Passport', "Driver's License", 'National ID', 'UMID / SSS', 'PhilHealth', 'TIN', 'PRC', 'Postal ID', 'Company ID', 'School ID', 'Other'];
  const VIEWER_MS = 60 * 1000;      // photo viewer closes itself after 60s
  const MAX_IMAGE_PX = 2400;        // long side of saved photos
  const THUMB_PX = 320;
  const MAX_IMAGES = 6;             // per ID

  // ---------- State (in memory only) ----------
  const state = {
    key: null,          // CryptoKey (non-extractable) — present only while unlocked
    record: null,       // encrypted record as stored
    items: [],          // decrypted credentials — cleared on lock
    photos: [],         // decrypted ID metadata + small thumbnails — cleared on lock
    view: 'accounts',   // 'accounts' | 'photos'
    photoFilter: 'all',
    draft: null,        // ID being added/edited
    viewer: null,       // { docId, index, url, token }
    filter: 'all',
    query: '',
    sort: 'az',
    expandedId: null,
    editingId: null,
    lastActivity: Date.now(),
    mode: 'unlock',     // 'setup' | 'unlock'
    busy: false,
  };
  let revealTimer = null;
  let clipboardTimer = null;
  let toastTimer = null;
  let viewerTimer = null;

  const $ = (id) => document.getElementById(id);
  const te = new TextEncoder();
  const td = new TextDecoder();

  // =========================================================
  // Icons (static, trusted markup)
  // =========================================================
  const ICONS = {
    key: '<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3m-4 4 3 3m-5-1 2 2"/>',
    eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
    eyeOff: '<path d="M9.9 5.2A10.4 10.4 0 0 1 12 5c6.4 0 10 7 10 7a17.6 17.6 0 0 1-2.6 3.4M6.6 6.6C3.7 8.4 2 12 2 12s3.6 7 10 7a9.7 9.7 0 0 0 5.4-1.6M3 3l18 18M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
    copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
    check: '<path d="M20 6 9 17l-5-5"/>',
    edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
    trash: '<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>',
    external: '<path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
    star: '<path d="m12 2 3.1 6.3 6.9 1-5 4.9 1.2 6.8L12 17.8 5.8 21l1.2-6.8-5-4.9 6.9-1Z"/>',
    lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    unlock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.8-1.3"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    x: '<path d="M18 6 6 18M6 6l12 12"/>',
    more: '<circle cx="12" cy="5" r="1.2"/><circle cx="12" cy="12" r="1.2"/><circle cx="12" cy="19" r="1.2"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
    upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/>',
    refresh: '<path d="M21 12a9 9 0 1 1-2.6-6.4L21 8M21 3v5h-5"/>',
    clipboard: '<rect x="8" y="2" width="8" height="4" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/>',
    alert: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0ZM12 9v4M12 17h.01"/>',
    sort: '<path d="M3 6h13M3 12h9M3 18h5M17 10V20m0 0-3-3m3 3 3-3"/>',
    image: '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.1-3.1a2 2 0 0 0-2.8 0L6 21"/>',
    camera: '<path d="M14.5 4h-5L7 7H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-3Z"/><circle cx="12" cy="13" r="3.5"/>',
    idcard: '<rect x="2" y="5" width="20" height="14" rx="2"/><circle cx="8" cy="11" r="2"/><path d="M5 16c.6-1.4 1.7-2 3-2s2.4.6 3 2M14 10h5M14 14h3"/>',
    chevL: '<path d="m15 18-6-6 6-6"/>',
    chevR: '<path d="m9 18 6-6-6-6"/>',
    vault: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="12" cy="12" r="3.5"/><path d="M12 8.5V7M12 17v-1.5M7 20v1M17 20v1"/>',
  };

  function icon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('class', 'i');
    svg.setAttribute('aria-hidden', 'true');
    svg.innerHTML = ICONS[name] || '';
    return svg;
  }
  function hydrateIcons(root = document) {
    root.querySelectorAll('[data-icon]').forEach((el) => {
      if (!el.firstChild) el.appendChild(icon(el.dataset.icon));
    });
  }

  // Tiny DOM builder — always uses textContent, never innerHTML for user data.
  function h(tag, attrs = {}, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) {
      if (c == null || c === false) continue;
      el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return el;
  }

  // =========================================================
  // IndexedDB
  // =========================================================
  let dbPromise = null;
  function openDB() {
    if (!dbPromise) {
      dbPromise = new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, 2);
        req.onupgradeneeded = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
          if (!db.objectStoreNames.contains(FILES)) db.createObjectStore(FILES);
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    }
    return dbPromise;
  }
  async function dbGet() {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const req = db.transaction(STORE, 'readonly').objectStore(STORE).get(RECORD_KEY);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  }
  async function dbPut(value) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).put(value, RECORD_KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }
  async function dbDelete() {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).delete(RECORD_KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  // Encrypted photo files: key = fileId, value = { iv: base64, ct: ArrayBuffer }
  async function fileOp(mode, fn) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(FILES, mode);
      const req = fn(tx.objectStore(FILES));
      let out;
      if (req) req.onsuccess = () => { out = req.result; };
      tx.oncomplete = () => resolve(out);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  }
  const fileGet = (id) => fileOp('readonly', (st) => st.get(id));
  const filePut = (id, rec) => fileOp('readwrite', (st) => st.put(rec, id));
  const fileDelete = (id) => fileOp('readwrite', (st) => st.delete(id));
  const fileKeys = () => fileOp('readonly', (st) => st.getAllKeys());
  const fileClear = () => fileOp('readwrite', (st) => st.clear());

  // =========================================================
  // Crypto
  // =========================================================
  function toB64(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function fromB64(str) {
    return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
  }
  async function deriveKey(password, salt, iterations) {
    const base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      base,
      { name: 'AES-GCM', length: 256 },
      false,                          // non-extractable
      ['encrypt', 'decrypt']
    );
  }
  async function encryptPayload(key, payload) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(payload)));
    return { iv: toB64(iv), ct: toB64(ct) };
  }
  async function decryptPayload(key, record) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(record.iv) }, key, fromB64(record.ct));
    return JSON.parse(td.decode(pt));
  }
  async function encryptBytes(key, bytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
    return { iv: toB64(iv), ct };
  }
  async function decryptBytes(key, rec) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(rec.iv) }, key, rec.ct);
  }
  function validBackupFiles(files) {
    if (files === undefined) return [];
    if (!Array.isArray(files)) return null;
    const ok = files.filter((f) => f && typeof f.id === 'string' && f.id.length <= 64 &&
      typeof f.iv === 'string' && typeof f.ct === 'string');
    return ok.length === files.length ? ok : null;
  }
  function isValidRecord(r) {
    try {
      return !!r && r.format === 'keyvault' && r.version === 1 && r.kdf &&
        typeof r.kdf.salt === 'string' && fromB64(r.kdf.salt).length >= 16 &&
        Number.isInteger(r.kdf.iterations) && r.kdf.iterations >= MIN_ITER && r.kdf.iterations <= MAX_ITER &&
        typeof r.iv === 'string' && fromB64(r.iv).length === 12 &&
        typeof r.ct === 'string' && r.ct.length > 0;
    } catch { return false; }
  }
  async function openRecord(record, password) {
    const key = await deriveKey(password, fromB64(record.kdf.salt), record.kdf.iterations);
    try {
      const data = await decryptPayload(key, record);
      return { key, items: sanitizeItems(data && data.items), photos: sanitizePhotos(data && data.photos) };
    } catch {
      return null; // GCM auth failure = wrong password (or tampered data)
    }
  }
  const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '');
  function sanitizePhotos(list) {
    if (!Array.isArray(list)) return [];
    return list.filter((p) => p && typeof p === 'object').map((p) => ({
      id: str(p.id, 64) || uid(),
      title: str(p.title, 120) || 'Untitled',
      type: ID_TYPES.includes(p.type) ? p.type : 'Other',
      notes: str(p.notes, 2000),
      images: (Array.isArray(p.images) ? p.images : [])
        .filter((im) => im && typeof im.fileId === 'string')
        .slice(0, MAX_IMAGES)
        .map((im) => ({
          fileId: str(im.fileId, 64),
          label: str(im.label, 30),
          w: Number(im.w) || 0,
          h: Number(im.h) || 0,
          thumb: typeof im.thumb === 'string' && im.thumb.startsWith('data:image/jpeg;base64,') ? im.thumb : '',
        })),
      createdAt: Number(p.createdAt) || Date.now(),
      updatedAt: Number(p.updatedAt) || Number(p.createdAt) || Date.now(),
    }));
  }
  function sanitizeItems(list) {
    if (!Array.isArray(list)) return [];
    return list.filter((i) => i && typeof i === 'object').map((i) => ({
      id: str(i.id, 64) || uid(),
      name: str(i.name, 120) || 'Untitled',
      url: str(i.url, 500),
      username: str(i.username, 250),
      password: str(i.password, 500),
      notes: str(i.notes, 2000),
      category: CATEGORIES.includes(i.category) ? i.category : 'Other',
      favorite: !!i.favorite,
      createdAt: Number(i.createdAt) || Date.now(),
      updatedAt: Number(i.updatedAt) || Number(i.createdAt) || Date.now(),
    }));
  }
  async function persist() {
    const { iv, ct } = await encryptPayload(state.key, { items: state.items, photos: state.photos });
    state.record = { ...state.record, iv, ct, savedAt: new Date().toISOString() };
    await dbPut(state.record);
  }
  function uid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    return toB64(crypto.getRandomValues(new Uint8Array(16))).replace(/[^a-z0-9]/gi, '');
  }

  // Unbiased secure random integer in [0, max)
  function randInt(max) {
    const limit = Math.floor(0x100000000 / max) * max;
    const buf = new Uint32Array(1);
    do crypto.getRandomValues(buf); while (buf[0] >= limit);
    return buf[0] % max;
  }
  function generatePassword(length = 20) {
    const sets = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#$%^&*-_=+?'];
    const all = sets.join('');
    const chars = sets.map((s) => s[randInt(s.length)]);
    while (chars.length < length) chars.push(all[randInt(all.length)]);
    for (let i = chars.length - 1; i > 0; i--) { const j = randInt(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
    return chars.join('');
  }

  // =========================================================
  // Lock screen
  // =========================================================
  function setLockMode(mode, info = '') {
    state.mode = mode;
    const setup = mode === 'setup';
    $('lockTitle').textContent = setup ? 'Create your vault' : 'Unlock your vault';
    $('lockHint').textContent = setup
      ? 'Choose a master password. It encrypts everything stored on this device.'
      : 'Enter your master password.';
    $('masterLabel').textContent = setup ? 'New master password' : 'Master password';
    $('masterInput').setAttribute('autocomplete', setup ? 'new-password' : 'current-password');
    $('setupFields').hidden = !setup;
    $('unlockBtnText').textContent = setup ? 'Create Vault' : 'Unlock Vault';
    $('restoreBtn').hidden = !setup;
    $('eraseBtn').hidden = setup;
    $('lockError').textContent = '';
    $('lockInfo').textContent = info;
    $('masterInput').value = '';
    $('confirmInput').value = '';
    updateStrength();
  }

  function showLockScreen() {
    $('app').hidden = true;
    $('lockScreen').hidden = false;
    setTimeout(() => $('masterInput').focus(), 50);
  }

  function updateStrength() {
    const pw = $('masterInput').value;
    let score = 0;
    if (pw.length >= MIN_MASTER_LEN) score++;
    if (pw.length >= 14) score++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
    if (/\d/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    const pct = pw ? Math.max(8, score * 20) : 0;
    const fill = $('strengthFill');
    fill.style.width = pct + '%';
    fill.style.background = score <= 2 ? 'var(--danger)' : score === 3 ? '#FFC478' : 'var(--ok)';
    $('strengthText').textContent = !pw ? `At least ${MIN_MASTER_LEN} characters`
      : pw.length < MIN_MASTER_LEN ? `${MIN_MASTER_LEN - pw.length} more characters`
      : ['Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very strong'][score];
  }

  async function handleLockSubmit(e) {
    e.preventDefault();
    if (state.busy) return;
    const pw = $('masterInput').value;
    $('lockError').textContent = '';
    $('lockInfo').textContent = '';

    if (state.mode === 'setup') {
      if (pw.length < MIN_MASTER_LEN) return lockError(`Use at least ${MIN_MASTER_LEN} characters.`);
      if (pw !== $('confirmInput').value) return lockError('The passwords do not match.');
      await withBusy(async () => {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        state.key = await deriveKey(pw, salt, KDF_ITERATIONS);
        state.items = [];
        state.photos = [];
        await fileClear();
        state.record = {
          format: 'keyvault', version: 1, app: 'KEYVAULT',
          kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: KDF_ITERATIONS, salt: toB64(salt) },
          cipher: 'AES-256-GCM',
        };
        await persist();
        requestPersistentStorage();
        enterApp();
        toast('Vault created');
      }, 'Creating…');
      return;
    }

    if (!pw) return lockError('Enter your master password.');
    await withBusy(async () => {
      const record = await dbGet();
      if (!record || !isValidRecord(record)) { setLockMode('setup'); return lockError('No vault found on this device.'); }
      const opened = await openRecord(record, pw);
      if (!opened) {
        $('masterInput').select();
        return lockError('Incorrect master password.');
      }
      state.key = opened.key;
      state.items = opened.items;
      state.photos = opened.photos;
      state.record = record;
      cleanupOrphanFiles();
      requestPersistentStorage();
      enterApp();
    }, 'Unlocking…');
  }

  async function withBusy(fn, label) {
    state.busy = true;
    const btn = $('unlockBtn');
    const txt = $('unlockBtnText');
    btn.disabled = true;
    txt.textContent = label;
    try { await fn(); }
    catch { lockError('Something went wrong. Please try again.'); }
    finally {
      state.busy = false;
      btn.disabled = false;
      txt.textContent = state.mode === 'setup' ? 'Create Vault' : 'Unlock Vault';
    }
  }

  function lockError(msg) {
    $('lockError').textContent = msg;
    const card = document.querySelector('.lock-card');
    card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake');
  }

  function requestPersistentStorage() {
    if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
  }

  function enterApp() {
    $('masterInput').value = '';
    $('confirmInput').value = '';
    $('lockScreen').hidden = true;
    $('app').hidden = false;
    state.lastActivity = Date.now();
    state.expandedId = null;
    render();
  }

  function lockVault(message = '') {
    collapse(false);
    state.key = null;
    closeViewer();
    state.items = [];
    state.photos = [];
    state.draft = null;
    state.record = null;
    state.editingId = null;
    $('list').replaceChildren();
    $('photoGrid').replaceChildren();
    $('imgSlots').replaceChildren();
    ['editDialog', 'askDialog', 'photoDialog'].forEach((id) => { const d = $(id); if (d.open) d.close(); });
    clearEditForm();
    closeMenu();
    $('searchInput').value = '';
    state.query = '';
    setLockMode('unlock', message);
    showLockScreen();
  }

  // =========================================================
  // Auto-lock on inactivity
  // =========================================================
  function markActive() { state.lastActivity = Date.now(); }
  ['pointerdown', 'keydown', 'wheel', 'touchstart', 'input'].forEach((ev) =>
    document.addEventListener(ev, markActive, { capture: true, passive: true }));

  function checkIdle() {
    if (state.key && Date.now() - state.lastActivity >= AUTO_LOCK_MS) {
      lockVault('Locked after 5 minutes of inactivity.');
    }
  }
  setInterval(checkIdle, 5000);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { collapse(); closeViewer(); }   // hide secrets when switching apps
    else checkIdle();                       // timers may have been paused while asleep
  });

  // =========================================================
  // Rendering
  // =========================================================
  function visibleItems() {
    const q = state.query.trim().toLowerCase();
    let list = state.items.filter((i) => {
      if (state.filter === 'fav' && !i.favorite) return false;
      if (state.filter !== 'all' && state.filter !== 'fav' && i.category !== state.filter) return false;
      if (!q) return true;
      return [i.name, i.username, i.category, i.url].some((f) => (f || '').toLowerCase().includes(q));
    });
    const byName = (a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base', numeric: true });
    const sorters = {
      az: (a, b) => (b.favorite - a.favorite) || byName(a, b),
      za: (a, b) => (b.favorite - a.favorite) || byName(b, a),
      added: (a, b) => b.createdAt - a.createdAt,
      updated: (a, b) => b.updatedAt - a.updatedAt,
    };
    return list.sort(sorters[state.sort] || sorters.az);
  }

  function render() {
    renderHeader();
    renderChips();
    renderView();
  }

  function renderView() {
    const photos = state.view === 'photos';
    $('list').hidden = photos;
    $('photoGrid').hidden = !photos;
    if (photos) renderPhotos(); else renderList();
  }

  function renderHeader() {
    $('tabCountA').textContent = String(state.items.length);
    $('tabCountP').textContent = String(state.photos.length);
    document.querySelectorAll('.tab').forEach((t) => {
      const on = t.dataset.view === state.view;
      t.classList.toggle('on', on);
      t.setAttribute('aria-selected', String(on));
    });
    const n = state.items.length;
    $('countBadge').replaceChildren(h('b', { text: String(n) }), h('span', { class: 'hide-xs', text: n === 1 ? ' account' : ' accounts' }));
    $('countBadge').title = `${n} saved account${n === 1 ? '' : 's'}`;
  }

  function renderChips() {
    if (state.view === 'photos') return renderPhotoChips();
    const counts = { all: state.items.length, fav: state.items.filter((i) => i.favorite).length };
    CATEGORIES.forEach((c) => { counts[c] = state.items.filter((i) => i.category === c).length; });
    const defs = [['all', 'All'], ['fav', 'Favorites'], ...CATEGORIES.map((c) => [c, c])];
    const chips = defs
      .filter(([k]) => k === 'all' || k === 'fav' || counts[k] > 0 || state.filter === k)
      .map(([k, label]) => h('button', {
        class: 'chip' + (state.filter === k ? ' on' : ''), role: 'tab', 'aria-selected': String(state.filter === k), type: 'button',
        onclick: () => { state.filter = k; collapse(false); render(); },
      }, k === 'fav' ? icon('star') : null, label, h('span', { class: 'n', text: String(counts[k]) })));
    $('chips').replaceChildren(...chips);
  }

  function renderPhotoChips() {
    const counts = { all: state.photos.length };
    ID_TYPES.forEach((t) => { counts[t] = state.photos.filter((p) => p.type === t).length; });
    const defs = [['all', 'All'], ...ID_TYPES.map((t) => [t, t])];
    const chips = defs
      .filter(([k]) => k === 'all' || counts[k] > 0 || state.photoFilter === k)
      .map(([k, label]) => h('button', {
        class: 'chip' + (state.photoFilter === k ? ' on' : ''), role: 'tab', 'aria-selected': String(state.photoFilter === k), type: 'button',
        onclick: () => { state.photoFilter = k; render(); },
      }, label, h('span', { class: 'n', text: String(counts[k]) })));
    $('chips').replaceChildren(...chips);
  }

  function renderList() {
    const items = visibleItems();
    const list = $('list');
    const empty = $('emptyState');
    const meta = $('listMeta');

    if (state.expandedId && !items.some((i) => i.id === state.expandedId)) collapse(false);

    list.replaceChildren(...items.map(renderRow));

    const filtering = state.query.trim() || state.filter !== 'all';
    meta.hidden = !filtering || items.length === 0;
    meta.textContent = `Showing ${items.length} of ${state.items.length}`;

    if (state.items.length === 0) {
      empty.replaceChildren(
        h('div', { class: 'big' }, icon('vault')),
        h('h3', { text: 'Your vault is empty' }),
        h('p', { text: 'Add the logins you have been emailing to yourself. Tip: use “Paste from email” to fill the fields in one go.' }),
        h('button', { class: 'btn primary', type: 'button', onclick: () => openEditor() }, icon('plus'), 'Add your first credential')
      );
      empty.hidden = false;
    } else if (items.length === 0) {
      empty.replaceChildren(
        h('div', { class: 'big' }, icon('search')),
        h('h3', { text: 'No matches' }),
        h('p', { text: state.query ? `Nothing matches “${state.query.trim()}”.` : 'No accounts in this category yet.' }),
        h('button', { class: 'btn ghost', type: 'button', onclick: resetFilters }, 'Clear search & filters')
      );
      empty.hidden = false;
    } else {
      empty.hidden = true;
    }
  }

  function resetFilters() {
    state.query = ''; state.filter = 'all'; state.photoFilter = 'all';
    $('searchInput').value = '';
    $('clearSearch').hidden = true;
    render();
  }

  function avatarColors(name) {
    let hash = 0;
    for (const ch of name.toLowerCase()) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
    const hue = hash % 360;
    return { bg: `hsl(${hue} 32% 22%)`, fg: `hsl(${hue} 70% 82%)` };
  }

  function renderRow(item) {
    const open = state.expandedId === item.id;
    const colors = avatarColors(item.name);
    const avatar = h('div', { class: 'avatar', 'aria-hidden': 'true', text: (item.name.trim()[0] || '?') });
    avatar.style.background = colors.bg;
    avatar.style.color = colors.fg;

    const eyeBtn = h('button', {
      class: 'icon-btn' + (open ? ' active' : ''), type: 'button',
      'aria-label': open ? `Hide details for ${item.name}` : `Show details for ${item.name}`,
      'aria-expanded': String(open), title: open ? 'Hide details' : 'Show details',
      onclick: (e) => { e.stopPropagation(); toggleRow(item.id); },
    }, icon(open ? 'eyeOff' : 'eye'));

    const copyBtn = h('button', {
      class: 'icon-btn', type: 'button', 'aria-label': `Copy password for ${item.name}`, title: 'Copy password',
      onclick: (e) => { e.stopPropagation(); copyText(item.password, 'Password', copyBtn); },
    }, icon('copy'));

    const main = h('div', { class: 'row-main', onclick: () => toggleRow(item.id) },
      avatar,
      h('div', { class: 'row-text' },
        h('div', { class: 'row-name' },
          h('span', { class: 't', text: item.name }),
          item.favorite ? h('span', { class: 'star', title: 'Favorite' }, icon('star')) : null),
        h('div', { class: 'row-user', text: item.username || hostOf(item.url) || '—' })),
      h('div', { class: 'row-actions' }, eyeBtn, copyBtn));

    return h('li', { class: 'row' + (open ? ' open' : ''), 'data-id': item.id }, main, open ? renderDetail(item) : null);
  }

  function renderDetail(item) {
    const userCopy = h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Copy username', title: 'Copy username',
      onclick: () => copyText(item.username, 'Username', userCopy) }, icon('copy'));
    const passCopy = h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Copy password', title: 'Copy password',
      onclick: () => copyText(item.password, 'Password', passCopy) }, icon('copy'));
    const safeUrl = normalizeUrl(item.url);

    const rows = [];
    if (item.url) {
      rows.push(h('div', { class: 'd-row' },
        h('span', { class: 'd-label', text: 'Website' }),
        h('span', { class: 'd-val' }, safeUrl
          ? h('a', { href: safeUrl, target: '_blank', rel: 'noopener noreferrer', text: item.url })
          : item.url),
        h('span')));
    }
    rows.push(h('div', { class: 'd-row' },
      h('span', { class: 'd-label', text: 'Username' }),
      h('span', { class: 'd-val mono', text: item.username || '—' }),
      item.username ? userCopy : h('span')));
    rows.push(h('div', { class: 'd-row' },
      h('span', { class: 'd-label', text: 'Password' }),
      h('span', { class: 'd-val mono pw', text: item.password }),
      passCopy));
    rows.push(h('div', { class: 'd-row' },
      h('span', { class: 'd-label', text: 'Category' }),
      h('span', { class: 'd-val' }, h('span', { class: 'd-tag', text: item.category })),
      h('span')));
    if (item.notes) {
      rows.push(h('div', { class: 'd-row' },
        h('span', { class: 'd-label', text: 'Notes' }),
        h('span', { class: 'd-val notes', text: item.notes }),
        h('span')));
    }

    const bar = h('span');
    bar.style.animationDuration = REVEAL_MS + 'ms';

    return h('div', { class: 'detail' },
      h('div', { class: 'd-grid' }, rows),
      h('div', { class: 'd-actions' },
        safeUrl ? h('button', { class: 'btn ghost', type: 'button', onclick: () => openSite(safeUrl) }, icon('external'), 'Open') : null,
        h('button', { class: 'btn ghost', type: 'button', onclick: () => openEditor(item.id) }, icon('edit'), 'Edit'),
        h('button', { class: 'btn ghost' + (item.favorite ? ' fav-on' : ''), type: 'button', 'aria-pressed': String(item.favorite),
          onclick: () => toggleFavorite(item.id) }, icon('star'), item.favorite ? 'Pinned' : 'Pin'),
        h('button', { class: 'btn ghost del', type: 'button', onclick: () => deleteItem(item.id) }, icon('trash'), 'Delete'),
        h('span', { class: 'd-timer', title: 'Hides automatically' }, 'Auto-hide', h('span', { class: 'bar' }, bar))));
  }

  // =========================================================
  // Row expand / collapse
  // =========================================================
  function toggleRow(id) {
    if (state.expandedId === id) { collapse(); return; }
    clearTimeout(revealTimer);
    state.expandedId = id;
    renderList();
    revealTimer = setTimeout(() => collapse(), REVEAL_MS);
    const row = $('list').querySelector(`[data-id="${CSS.escape(id)}"]`);
    if (row) row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }

  function collapse(rerender = true) {
    clearTimeout(revealTimer);
    revealTimer = null;
    if (state.expandedId === null) return;
    state.expandedId = null;
    if (rerender && state.key) renderList();
    else {
      // remove the revealed password from the DOM immediately
      const d = document.querySelector('.row.open .detail');
      if (d) d.remove();
    }
  }

  // =========================================================
  // ID Photos — page
  // =========================================================
  function visiblePhotos() {
    const q = state.query.trim().toLowerCase();
    const list = state.photos.filter((p) => {
      if (state.photoFilter !== 'all' && p.type !== state.photoFilter) return false;
      if (!q) return true;
      return [p.title, p.type, p.notes].some((f) => (f || '').toLowerCase().includes(q));
    });
    const byTitle = (a, b) => a.title.localeCompare(b.title, undefined, { sensitivity: 'base', numeric: true });
    const sorters = {
      az: byTitle,
      za: (a, b) => byTitle(b, a),
      added: (a, b) => b.createdAt - a.createdAt,
      updated: (a, b) => b.updatedAt - a.updatedAt,
    };
    return list.sort(sorters[state.sort] || sorters.az);
  }

  function renderPhotos() {
    const docs = visiblePhotos();
    const meta = $('listMeta');
    const empty = $('emptyState');
    $('photoGrid').replaceChildren(...docs.map(photoCard));

    const filtering = state.query.trim() || state.photoFilter !== 'all';
    meta.hidden = state.photos.length === 0;
    meta.textContent = filtering ? `Showing ${docs.length} of ${state.photos.length}` : 'Tap an ID to view it. Photos close automatically after 60 seconds.';
    if (!filtering) updateStorageNote();

    if (state.photos.length === 0) {
      empty.replaceChildren(
        h('div', { class: 'big' }, icon('idcard')),
        h('h3', { text: 'No ID photos yet' }),
        h('p', { text: 'Save photos of your passport, driver’s license, national ID and more. They are encrypted on this device just like your passwords.' }),
        h('button', { class: 'btn primary', type: 'button', onclick: () => openPhotoEditor() }, icon('camera'), 'Add your first ID')
      );
      empty.hidden = false;
    } else if (docs.length === 0) {
      empty.replaceChildren(
        h('div', { class: 'big' }, icon('search')),
        h('h3', { text: 'No matches' }),
        h('p', { text: state.query ? `Nothing matches “${state.query.trim()}”.` : 'No IDs of this type yet.' }),
        h('button', { class: 'btn ghost', type: 'button', onclick: resetFilters }, 'Clear search & filters')
      );
      empty.hidden = false;
    } else {
      empty.hidden = true;
    }
  }

  async function updateStorageNote() {
    if (!navigator.storage || !navigator.storage.estimate) return;
    try {
      const { usage } = await navigator.storage.estimate();
      if (state.view === 'photos' && !state.query.trim() && state.photoFilter === 'all' && state.photos.length) {
        $('listMeta').textContent = `Tap an ID to view it · ${formatBytes(usage || 0)} used on this device`;
      }
    } catch { /* ignore */ }
  }
  function formatBytes(n) {
    if (n < 1024 * 1024) return Math.max(1, Math.round(n / 1024)) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }

  function photoCard(doc) {
    const first = doc.images[0];
    const thumb = first && first.thumb
      ? h('img', { src: first.thumb, alt: '', draggable: 'false' })
      : h('span', { class: 'ph-none' }, icon('image'));
    return h('button', { class: 'ph-card', type: 'button', 'data-id': doc.id, 'aria-label': `View ${doc.title}`,
      onclick: () => openViewer(doc.id, 0) },
      h('span', { class: 'ph-thumb' }, thumb,
        h('span', { class: 'ph-eye' }, icon('eye')),
        doc.images.length > 1 ? h('span', { class: 'ph-count' }, icon('image'), String(doc.images.length)) : null),
      h('span', { class: 'ph-info' },
        h('span', { class: 'ph-title', text: doc.title }),
        h('span', { class: 'ph-type', text: doc.type })));
  }

  // ---------- image processing (resize, re-encode = strips EXIF/GPS) ----------
  function loadBitmap(file) {
    if (window.createImageBitmap) {
      return createImageBitmap(file).catch(() => loadViaImg(file));
    }
    return loadViaImg(file);
  }
  function loadViaImg(file) {
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(file);
      const img = new Image();
      img.onload = () => { URL.revokeObjectURL(url); resolve(img); };
      img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('decode')); };
      img.src = url;
    });
  }
  function drawScaled(src, maxPx) {
    const w0 = src.width, h0 = src.height;
    const scale = Math.min(1, maxPx / Math.max(w0, h0));
    const w = Math.max(1, Math.round(w0 * scale)), hgt = Math.max(1, Math.round(h0 * scale));
    const c = document.createElement('canvas');
    c.width = w; c.height = hgt;
    const ctx = c.getContext('2d');
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, w, hgt);
    ctx.drawImage(src, 0, 0, w, hgt);
    return c;
  }
  function canvasToBlob(c, quality) {
    return new Promise((resolve, reject) => c.toBlob((b) => (b ? resolve(b) : reject(new Error('encode'))), 'image/jpeg', quality));
  }
  async function processImage(file) {
    if (!file.type.startsWith('image/') && !/\.(heic|heif|jpe?g|png|webp|gif)$/i.test(file.name)) throw new Error('type');
    const src = await loadBitmap(file);
    const full = drawScaled(src, MAX_IMAGE_PX);
    const blob = await canvasToBlob(full, 0.9);
    const thumb = drawScaled(full, THUMB_PX).toDataURL('image/jpeg', 0.72);
    if (src.close) src.close();
    return { bytes: await blob.arrayBuffer(), w: full.width, h: full.height, thumb };
  }

  // ---------- add / edit ID ----------
  function fillTypeSelect() {
    $('pType').replaceChildren(...ID_TYPES.map((t) => h('option', { value: t, text: t })));
  }
  function defaultLabel(i) { return ['Front', 'Back'][i] || `Page ${i + 1}`; }

  function openPhotoEditor(id = null) {
    closeViewer();
    closeMenu();
    const doc = id ? state.photos.find((p) => p.id === id) : null;
    state.draft = {
      id,
      images: doc ? doc.images.map((im) => ({ ...im, existing: true })) : [],
      removed: [],
    };
    $('photoTitle').textContent = doc ? 'Edit ID' : 'Add ID';
    $('pTitle').value = doc ? doc.title : '';
    $('pType').value = doc ? doc.type : (ID_TYPES.includes(state.photoFilter) ? state.photoFilter : 'Passport');
    $('pNotes').value = doc ? doc.notes : '';
    $('photoError').textContent = '';
    renderSlots();
    $('photoDialog').showModal();
    if (!doc && !matchMedia('(max-width: 680px)').matches) $('pTitle').focus();
  }

  function renderSlots() {
    const d = state.draft;
    if (!d) return;
    const slots = d.images.map((im, i) => {
      const label = h('input', { type: 'text', class: 'slot-label', maxlength: '30', value: im.label || defaultLabel(i), 'aria-label': `Label for photo ${i + 1}` });
      label.addEventListener('input', () => { im.label = label.value.trim(); });
      if (!im.label) im.label = defaultLabel(i);
      const img = h('img', { src: im.thumb, alt: '' });
      return h('div', { class: 'slot' },
        h('div', { class: 'slot-img' }, img,
          h('button', { type: 'button', class: 'slot-x', 'aria-label': `Remove photo ${i + 1}`, onclick: () => removeSlot(i) }, icon('x'))),
        label);
    });
    if (d.images.length < MAX_IMAGES) {
      slots.push(h('button', { type: 'button', class: 'slot-add', id: 'addImgBtn', onclick: () => $('photoInput').click() },
        icon('camera'), h('span', { text: d.busy ? 'Processing…' : 'Add photo' })));
    }
    $('imgSlots').replaceChildren(...slots);
  }

  function removeSlot(i) {
    const d = state.draft;
    const [im] = d.images.splice(i, 1);
    if (im && im.existing) d.removed.push(im.fileId);
    renderSlots();
  }

  async function handlePhotoFiles() {
    const input = $('photoInput');
    const files = Array.from(input.files || []);
    input.value = '';
    const d = state.draft;
    if (!d || !files.length) return;
    const room = MAX_IMAGES - d.images.length;
    if (files.length > room) toast(`Only ${MAX_IMAGES} photos per ID — extra ones skipped`, true);
    d.busy = true; renderSlots();
    let failed = 0;
    for (const f of files.slice(0, room)) {
      try {
        const out = await processImage(f);
        if (state.draft !== d) return;          // dialog closed / vault locked meanwhile
        d.images.push({ ...out, label: defaultLabel(d.images.length), existing: false });
      } catch { failed++; }
    }
    d.busy = false;
    renderSlots();
    $('photoError').textContent = failed ? 'Some images could not be read. Try a JPG or PNG (or take the photo with your camera).' : '';
  }

  async function savePhotoDoc() {
    const d = state.draft;
    if (!d || d.busy) return;
    const title = $('pTitle').value.trim();
    if (!title) { $('photoError').textContent = 'Please give this ID a name.'; $('pTitle').focus(); return; }
    if (!d.images.length) { $('photoError').textContent = 'Add at least one photo.'; return; }
    const btn = $('photoSaveBtn');
    btn.disabled = true; btn.textContent = 'Encrypting…';
    const written = [];
    const snapshot = state.photos.slice();
    try {
      const images = [];
      for (const im of d.images) {
        let fileId = im.fileId;
        if (!im.existing) {
          fileId = uid();
          await filePut(fileId, await encryptBytes(state.key, im.bytes));
          written.push(fileId);
        }
        images.push({ fileId, label: (im.label || '').slice(0, 30), w: im.w, h: im.h, thumb: im.thumb });
      }
      const now = Date.now();
      const data = { title: title.slice(0, 120), type: $('pType').value, notes: $('pNotes').value.trim().slice(0, 2000), images };
      if (d.id) state.photos = state.photos.map((p) => (p.id === d.id ? { ...p, ...data, updatedAt: now } : p));
      else state.photos = [...state.photos, { id: uid(), ...data, createdAt: now, updatedAt: now }];
      await persist();
      for (const fid of d.removed) await fileDelete(fid).catch(() => {});
      const wasEdit = !!d.id;
      state.draft = null;
      $('photoDialog').close();
      render();
      toast(wasEdit ? 'ID updated' : `${title} saved`);
    } catch {
      state.photos = snapshot;
      for (const fid of written) await fileDelete(fid).catch(() => {});
      $('photoError').textContent = 'Could not save. This device may be out of storage space.';
    } finally {
      btn.disabled = false; btn.textContent = 'Save ID';
    }
  }

  async function deletePhotoDoc(id) {
    const doc = state.photos.find((p) => p.id === id);
    if (!doc) return;
    clearTimeout(viewerTimer);
    const ok = await ask({ title: 'Delete this ID?', message: `“${doc.title}” and its ${doc.images.length} photo${doc.images.length === 1 ? '' : 's'} will be permanently removed from this vault.`, okText: 'Delete', danger: true });
    if (!ok) { if ($('viewerDialog').open) startViewerTimer(); return; }
    closeViewer();
    state.photos = state.photos.filter((p) => p.id !== id);
    await persist();
    for (const im of doc.images) await fileDelete(im.fileId).catch(() => {});
    render();
    toast('ID deleted');
  }

  async function cleanupOrphanFiles() {
    try {
      const used = new Set(state.photos.flatMap((p) => p.images.map((im) => im.fileId)));
      const keys = await fileKeys();
      for (const k of keys) if (!used.has(k)) await fileDelete(k);
    } catch { /* not critical */ }
  }

  // ---------- full-screen viewer ----------
  async function openViewer(docId, index = 0) {
    const doc = state.photos.find((p) => p.id === docId);
    if (!doc || !state.key) return;
    state.viewer = { docId, index, url: null, token: 0 };
    $('vTitle').textContent = doc.title;
    $('vNotes').textContent = doc.notes;
    $('vNotes').hidden = !doc.notes;
    if (!$('viewerDialog').open) $('viewerDialog').showModal();
    startViewerTimer();
    await showViewerImage();
  }

  function startViewerTimer() {
    clearTimeout(viewerTimer);
    viewerTimer = setTimeout(closeViewer, VIEWER_MS);
    const bar = h('span');
    bar.style.animationDuration = VIEWER_MS + 'ms';
    $('vTimer').replaceChildren('Auto-close', h('span', { class: 'bar' }, bar));
  }

  async function showViewerImage() {
    const v = state.viewer;
    if (!v) return;
    const doc = state.photos.find((p) => p.id === v.docId);
    if (!doc) return closeViewer();
    const n = doc.images.length;
    v.index = Math.max(0, Math.min(v.index, n - 1));
    const im = doc.images[v.index];
    const token = ++v.token;
    $('vSub').textContent = `${doc.type} · ${im.label || defaultLabel(v.index)}${n > 1 ? ` · ${v.index + 1} of ${n}` : ''}`;
    $('vPrev').hidden = $('vNext').hidden = n < 2;
    $('vPrev').disabled = v.index === 0;
    $('vNext').disabled = v.index === n - 1;
    const img = $('vImg');
    img.hidden = true;
    $('vMsg').textContent = 'Decrypting…';
    $('vMsg').hidden = false;
    try {
      const rec = await fileGet(im.fileId);
      if (!rec) throw new Error('missing');
      const buf = await decryptBytes(state.key, rec);
      if (!state.viewer || state.viewer.token !== token) return;
      if (v.url) URL.revokeObjectURL(v.url);
      v.url = URL.createObjectURL(new Blob([buf], { type: 'image/jpeg' }));
      img.src = v.url;
      img.hidden = false;
      $('vMsg').hidden = true;
    } catch {
      if (state.viewer && state.viewer.token === token) $('vMsg').textContent = 'This photo could not be opened.';
    }
  }

  function stepViewer(delta) {
    if (!state.viewer) return;
    state.viewer.index += delta;
    startViewerTimer();
    showViewerImage();
  }

  function closeViewer() {
    clearTimeout(viewerTimer);
    const v = state.viewer;
    state.viewer = null;
    if (v && v.url) URL.revokeObjectURL(v.url);
    const img = $('vImg');
    img.removeAttribute('src');
    img.hidden = true;
    if ($('viewerDialog').open) $('viewerDialog').close();
  }

  function saveViewerCopy() {
    const v = state.viewer;
    if (!v || !v.url) return;
    const doc = state.photos.find((p) => p.id === v.docId);
    const im = doc.images[v.index];
    const name = `${doc.title}-${im.label || v.index + 1}`.replace(/[^\w\- ]+/g, '').trim().replace(/\s+/g, '-') || 'id-photo';
    const a = h('a', { href: v.url, download: `${name}.jpg` });
    document.body.appendChild(a);
    a.click();
    a.remove();
    toast('Saved an unencrypted copy — delete it when done', false, true);
  }

  function setView(view) {
    if (state.view === view) return;
    state.view = view;
    state.query = '';
    $('searchInput').value = '';
    $('clearSearch').hidden = true;
    collapse(false);
    closeViewer();
    const photos = view === 'photos';
    $('searchInput').placeholder = photos ? 'Search ID name, type or notes' : 'Search name, user or category';
    $('addLabel').textContent = photos ? 'Add ID' : 'Add Credential';
    $('addBtn').setAttribute('aria-label', photos ? 'Add ID' : 'Add Credential');
    $('fab').setAttribute('aria-label', photos ? 'Add ID' : 'Add Credential');
    $('listWrap').scrollTop = 0;
    render();
  }

  // =========================================================
  // Clipboard
  // =========================================================
  async function copyText(text, label, btn) {
    if (!text) { toast(`No ${label.toLowerCase()} saved`, true); return; }
    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch {
      ok = legacyCopy(text);
    }
    if (!ok) { toast('Copy not allowed by this browser', true); return; }
    toast(`${label} copied`, false, true);
    if (btn) {
      btn.classList.add('done');
      btn.replaceChildren(icon('check'));
      setTimeout(() => { btn.classList.remove('done'); btn.replaceChildren(icon('copy')); }, 1400);
    }
    clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(clearClipboard, CLIPBOARD_CLEAR_MS);
  }
  function legacyCopy(text) {
    const ta = h('textarea', { 'aria-hidden': 'true', readonly: true });
    ta.value = text;
    ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0;';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.value = '';
    ta.remove();
    return ok;
  }
  function clearClipboard() {
    // Browsers only allow clipboard writes while the page is focused.
    if (navigator.clipboard && document.hasFocus()) navigator.clipboard.writeText('').catch(() => {});
  }

  // =========================================================
  // Add / edit
  // =========================================================
  function fillCategorySelect() {
    $('fCat').replaceChildren(...CATEGORIES.map((c) => h('option', { value: c, text: c })));
  }

  function openEditor(id = null) {
    collapse();
    closeMenu();
    clearEditForm();
    state.editingId = id;
    const item = id ? state.items.find((i) => i.id === id) : null;
    $('editTitle').textContent = item ? 'Edit Credential' : 'Add Credential';
    $('saveNewBtn').hidden = !!item;
    $('pasteBox').hidden = !!item;
    if (item) {
      $('fName').value = item.name;
      $('fUrl').value = item.url;
      $('fUser').value = item.username;
      $('fPass').value = item.password;
      $('fNotes').value = item.notes;
      $('fCat').value = item.category;
      $('fFav').checked = item.favorite;
    } else {
      $('fCat').value = (CATEGORIES.includes(state.filter) ? state.filter : 'Personal');
      $('fFav').checked = state.filter === 'fav';
    }
    $('editDialog').showModal();
    if (!matchMedia('(max-width: 680px)').matches) $('fName').focus();
  }

  function clearEditForm() {
    ['fName', 'fUrl', 'fUser', 'fPass', 'fNotes', 'pasteText'].forEach((id) => { $(id).value = ''; });
    $('fFav').checked = false;
    $('fPass').type = 'password';
    syncRevealButton('fPass');
    $('editError').textContent = '';
    $('pasteBox').open = false;
  }

  async function saveCredential(keepOpen) {
    const name = $('fName').value.trim();
    const password = $('fPass').value;
    if (!name) { $('editError').textContent = 'Please enter the website or application name.'; $('fName').focus(); return; }
    if (!password) { $('editError').textContent = 'Please enter a password (or tap Generate).'; $('fPass').focus(); return; }
    const data = {
      name: name.slice(0, 120),
      url: $('fUrl').value.trim().slice(0, 500),
      username: $('fUser').value.trim().slice(0, 250),
      password: password.slice(0, 500),
      notes: $('fNotes').value.trim().slice(0, 2000),
      category: $('fCat').value,
      favorite: $('fFav').checked,
    };
    const now = Date.now();
    const editing = state.editingId;
    const snapshot = state.items.slice();
    if (editing) {
      state.items = state.items.map((i) => (i.id === editing ? { ...i, ...data, updatedAt: now } : i));
    } else {
      state.items = [...state.items, { id: uid(), ...data, createdAt: now, updatedAt: now }];
    }
    try {
      await persist();
    } catch {
      state.items = snapshot;
      $('editError').textContent = 'Could not save. Storage may be full or blocked.';
      return;
    }
    render();
    toast(editing ? 'Changes saved' : `${data.name} added`);
    if (keepOpen) {
      clearEditForm();
      $('fCat').value = data.category;
      $('fName').focus();
    } else {
      $('editDialog').close();
    }
  }

  function closeEditor() {
    if ($('editDialog').open) $('editDialog').close();
  }

  // Parse text pasted from an email into fields
  function parsePasted() {
    const text = $('pasteText').value;
    if (!text.trim()) { $('editError').textContent = 'Paste some text first.'; return; }
    const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    const grab = (re) => { for (const l of lines) { const m = l.match(re); if (m) return m[1].trim(); } return ''; };

    const url = (text.match(/https?:\/\/[^\s<>"')]+/i) || text.match(/\bwww\.[^\s<>"')]+/i) || [])[0] || '';
    const pass = grab(/^(?:password|passcode|pass|pwd|pw|pin)\s*[:=\-–]\s*(.+)$/i);
    let user = grab(/^(?:user\s*name|username|user\s*id|user|login|log-in|e-?mail(?:\s*address)?|account|id)\s*[:=\-–]\s*(.+)$/i);
    if (!user) user = (text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i) || [])[0] || '';
    let name = grab(/^(?:site|website|app|application|service|name|platform)\s*[:=\-–]\s*(.+)$/i);
    if (!name && url) name = nameFromUrl(url);

    let filled = 0;
    if (url) { $('fUrl').value = url; filled++; }
    if (user) { $('fUser').value = user; filled++; }
    if (pass) { $('fPass').value = pass; filled++; }
    if (name && !$('fName').value) { $('fName').value = name; filled++; }
    $('pasteText').value = '';     // do not leave the pasted secret lying around
    $('editError').textContent = filled ? '' : 'Could not detect fields — try labels like “Username:” and “Password:”.';
    if (filled) { $('pasteBox').open = false; toast(`Filled ${filled} field${filled === 1 ? '' : 's'} — please check`); }
  }

  // =========================================================
  // Favorites / delete / open
  // =========================================================
  async function toggleFavorite(id) {
    const item = state.items.find((i) => i.id === id);
    if (!item) return;
    item.favorite = !item.favorite;
    item.updatedAt = Date.now();
    await persist();
    render();
    toast(item.favorite ? 'Pinned to top' : 'Unpinned');
  }

  async function deleteItem(id) {
    const item = state.items.find((i) => i.id === id);
    if (!item) return;
    clearTimeout(revealTimer); // keep the row open while confirming
    const ok = await ask({ title: 'Delete credential?', message: `“${item.name}” will be permanently removed from this vault.`, okText: 'Delete', danger: true });
    if (!ok) { revealTimer = setTimeout(() => collapse(), REVEAL_MS); return; }
    state.items = state.items.filter((i) => i.id !== id);
    state.expandedId = null;
    await persist();
    render();
    toast('Credential deleted');
  }

  function openSite(url) {
    const w = window.open(url, '_blank', 'noopener,noreferrer');
    if (w) w.opener = null;
  }

  function normalizeUrl(raw) {
    if (!raw) return '';
    let s = raw.trim();
    if (!/^[a-z][a-z0-9+.-]*:/i.test(s)) s = 'https://' + s;
    try {
      const u = new URL(s);
      return (u.protocol === 'https:' || u.protocol === 'http:') ? u.href : '';
    } catch { return ''; }
  }
  function hostOf(raw) {
    const u = normalizeUrl(raw);
    try { return u ? new URL(u).hostname.replace(/^www\./, '') : ''; } catch { return ''; }
  }
  function nameFromUrl(raw) {
    const host = hostOf(raw);
    if (!host) return '';
    const parts = host.split('.');
    const core = parts.length > 2 && parts[parts.length - 2].length <= 3 ? parts[parts.length - 3] : parts[parts.length - 2] || parts[0];
    return core ? core.charAt(0).toUpperCase() + core.slice(1) : '';
  }

  // =========================================================
  // Generic confirm / prompt dialog
  // =========================================================
  function ask({ title, message, okText = 'OK', danger = false, input = null }) {
    return new Promise((resolve) => {
      const dlg = $('askDialog');
      $('askTitle').textContent = title;
      $('askMessage').textContent = message;
      $('askError').textContent = '';
      $('askOk').textContent = okText;
      $('askOk').className = 'btn ' + (danger ? 'danger' : 'primary');
      $('askField').hidden = !input;
      const field = $('askInput');
      field.value = '';
      if (input) {
        $('askLabel').textContent = input.label;
        field.type = input.type || 'password';
      }
      let done = false;
      const finish = async (value) => {
        if (done) return;
        if (value !== null && input && input.validate) {
          const err = await input.validate(value);
          if (err) { $('askError').textContent = err; field.select(); return; }
        }
        done = true;
        cleanup();
        if (dlg.open) dlg.close();
        field.value = '';
        resolve(value);
      };
      const onSubmit = (e) => { e.preventDefault(); finish(input ? field.value : true); };
      const onCancel = (e) => { if (e) e.preventDefault(); finish(input ? null : false); };
      const cleanup = () => {
        $('askForm').removeEventListener('submit', onSubmit);
        $('askCancel').removeEventListener('click', onCancel);
        dlg.removeEventListener('cancel', onCancel);
        dlg.removeEventListener('close', onClose);
      };
      // ignore a late 'close' event left over from a previous use of this dialog
      const onClose = () => { if (!done && !dlg.open) { done = true; cleanup(); field.value = ''; resolve(input ? null : false); } };
      $('askForm').addEventListener('submit', onSubmit);
      $('askCancel').addEventListener('click', onCancel);
      dlg.addEventListener('cancel', onCancel);
      dlg.addEventListener('close', onClose);
      dlg.showModal();
      if (input) field.focus(); else $('askCancel').focus();
    });
  }

  // =========================================================
  // Backup export / import
  // =========================================================
  async function exportBackup() {
    closeMenu();
    if (!state.record) return;
    const files = [];
    try {
      const used = new Set(state.photos.flatMap((p) => p.images.map((im) => im.fileId)));
      for (const id of used) {
        const rec = await fileGet(id);
        if (rec) files.push({ id, iv: rec.iv, ct: toB64(rec.ct) });
      }
    } catch {
      toast('Could not read photos for the backup', true);
      return;
    }
    const payload = { ...state.record, files, exportedAt: new Date().toISOString() };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const d = new Date();
    const stamp = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
    const a = h('a', { href: url, download: `keyvault-backup-${stamp}.json` });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    toast('Encrypted backup downloaded');
  }

  function pickBackupFile() {
    return new Promise((resolve) => {
      const input = $('fileInput');
      input.value = '';
      input.onchange = async () => {
        const file = input.files && input.files[0];
        input.value = '';
        if (!file) return resolve(null);
        if (file.size > 1024 * 1024 * 1024) { toast('That file is too large to be a KEYVAULT backup', true); return resolve(null); }
        try {
          const rec = JSON.parse(await file.text());
          const files = rec && validBackupFiles(rec.files);
          if (!isValidRecord(rec) || !files) throw new Error('invalid');
          resolve({ format: rec.format, version: rec.version, app: 'KEYVAULT', kdf: rec.kdf, cipher: 'AES-256-GCM', iv: rec.iv, ct: rec.ct, files });
        } catch {
          toast('Not a valid KEYVAULT backup file', true);
          resolve(null);
        }
      };
      input.click();
    });
  }

  // From inside the vault: merge a backup into the current vault
  async function importIntoVault() {
    closeMenu();
    const rec = await pickBackupFile();
    if (!rec) return;
    let opened = null;
    const pw = await ask({
      title: 'Unlock backup',
      message: 'Enter the master password that was used when this backup was made.',
      okText: 'Decrypt',
      input: {
        label: 'Backup master password',
        validate: async (v) => {
          if (!v) return 'Enter the password.';
          opened = await openRecord(rec, v);
          return opened ? '' : 'Incorrect password for this backup.';
        },
      },
    });
    if (pw === null || !opened) return;

    const incoming = opened.items;
    const byId = new Map(state.items.map((i) => [i.id, i]));
    let added = 0, updated = 0, unchanged = 0;
    for (const it of incoming) {
      const cur = byId.get(it.id);
      if (!cur) added++;
      else if (it.updatedAt > cur.updatedAt) updated++;
      else unchanged++;
    }
    const photoById = new Map(state.photos.map((p) => [p.id, p]));
    const photoChanges = opened.photos.filter((p) => { const cur = photoById.get(p.id); return !cur || p.updatedAt > cur.updatedAt; });
    const ok = await ask({
      title: 'Merge backup?',
      message: `Backup contains ${incoming.length} credential${incoming.length === 1 ? '' : 's'} and ${opened.photos.length} ID${opened.photos.length === 1 ? '' : 's'}.\n\n• ${added} new account${added === 1 ? '' : 's'}\n• ${updated} newer version${updated === 1 ? '' : 's'} will replace yours\n• ${unchanged} already up to date\n• ${photoChanges.length} new or updated ID${photoChanges.length === 1 ? '' : 's'}\n\nNothing in your vault is deleted.`,
      okText: 'Merge',
    });
    if (!ok) return;
    toast('Merging…');
    // ID photos: decrypt with the backup's key, re-encrypt with THIS vault's key
    const backupFiles = new Map(rec.files.map((f) => [f.id, f]));
    let skipped = 0;
    for (const doc of photoChanges) {
      const keep = [];
      for (const im of doc.images) {
        const f = backupFiles.get(im.fileId);
        if (!f) { skipped++; continue; }
        try {
          const bytes = await decryptBytes(opened.key, { iv: f.iv, ct: fromB64(f.ct) });
          await filePut(im.fileId, await encryptBytes(state.key, bytes));
          keep.push(im);
        } catch { skipped++; }
      }
      photoById.set(doc.id, { ...doc, images: keep });
    }
    for (const it of incoming) {
      const cur = byId.get(it.id);
      if (!cur || it.updatedAt > cur.updatedAt) byId.set(it.id, it);
    }
    state.items = [...byId.values()];
    state.photos = [...photoById.values()];
    await persist();   // re-encrypted with THIS vault's key
    cleanupOrphanFiles();
    render();
    toast(`Merged: ${added} added, ${updated} updated, ${photoChanges.length} IDs` + (skipped ? ` (${skipped} photos missing)` : ''));
  }

  // From the setup screen: restore a backup as this device's vault
  async function restoreFromSetup() {
    const rec = await pickBackupFile();
    if (!rec) return;
    try {
      const { files, ...main } = rec;
      await fileClear();
      for (const f of files) await filePut(f.id, { iv: f.iv, ct: fromB64(f.ct).buffer });
      await dbPut(main);
    } catch {
      lockError('Could not write to this browser’s storage.');
      return;
    }
    setLockMode('unlock', 'Backup restored. Unlock it with the master password used for that backup.');
    $('masterInput').focus();
  }

  async function eraseVault() {
    const typed = await ask({
      title: 'Erase vault on this device?',
      message: 'Without the master password the data cannot be recovered. This permanently deletes the encrypted vault stored in this browser. Backups you downloaded are not affected.',
      okText: 'Erase',
      danger: true,
      input: { label: 'Type ERASE to confirm', type: 'text', validate: (v) => (v.trim() === 'ERASE' ? '' : 'Type ERASE in capital letters.') },
    });
    if (typed === null) return;
    await dbDelete();
    await fileClear().catch(() => {});
    setLockMode('setup', 'Vault erased. You can create a new one or restore a backup.');
  }

  // =========================================================
  // Misc UI
  // =========================================================
  function toast(msg, isError = false, withCheck = false) {
    const t = $('toast');
    t.replaceChildren(...(withCheck ? [icon('check')] : []), msg);
    t.classList.toggle('err', !!isError);
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 1700);
  }

  function syncRevealButton(inputId) {
    const btn = document.querySelector(`[data-reveal="${inputId}"]`);
    if (!btn) return;
    const shown = $(inputId).type === 'text';
    btn.replaceChildren(icon(shown ? 'eyeOff' : 'eye'));
    btn.setAttribute('aria-label', shown ? 'Hide password' : 'Show password');
  }

  function closeMenu() {
    $('menu').hidden = true;
    $('menuBtn').setAttribute('aria-expanded', 'false');
  }

  // =========================================================
  // Wire up events
  // =========================================================
  function bindEvents() {
    // Safety net: no form may ever submit natively (that would put data in a URL)
    document.querySelectorAll('form').forEach((f) => f.addEventListener('submit', (e) => e.preventDefault()));
    $('lockForm').addEventListener('submit', handleLockSubmit);
    $('masterInput').addEventListener('input', () => { $('lockError').textContent = ''; if (state.mode === 'setup') updateStrength(); });
    $('restoreBtn').addEventListener('click', restoreFromSetup);
    $('eraseBtn').addEventListener('click', eraseVault);

    document.querySelectorAll('[data-reveal]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const input = $(btn.dataset.reveal);
        input.type = input.type === 'password' ? 'text' : 'password';
        syncRevealButton(btn.dataset.reveal);
      });
    });

    $('lockBtn').addEventListener('click', () => lockVault('Vault locked.'));
    $('menuBtn').addEventListener('click', (e) => {
      e.stopPropagation();
      const open = $('menu').hidden;
      $('menu').hidden = !open;
      $('menuBtn').setAttribute('aria-expanded', String(open));
    });
    document.addEventListener('click', (e) => { if (!e.target.closest('.menu-wrap')) closeMenu(); });
    $('exportBtn').addEventListener('click', exportBackup);
    $('importBtn').addEventListener('click', importIntoVault);

    $('searchInput').addEventListener('input', (e) => {
      state.query = e.target.value;
      $('clearSearch').hidden = !state.query;
      renderView();
    });
    $('clearSearch').addEventListener('click', () => {
      $('searchInput').value = ''; state.query = ''; $('clearSearch').hidden = true; renderView(); $('searchInput').focus();
    });
    $('sortSelect').addEventListener('change', (e) => { state.sort = e.target.value; renderView(); });

    const addForView = () => (state.view === 'photos' ? openPhotoEditor() : openEditor());
    $('addBtn').addEventListener('click', addForView);
    $('fab').addEventListener('click', addForView);
    document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => setView(t.dataset.view)));

    // ID photos
    $('photoInput').addEventListener('change', handlePhotoFiles);
    $('photoForm').addEventListener('submit', (e) => { e.preventDefault(); savePhotoDoc(); });
    $('photoDialog').querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => $('photoDialog').close()));
    $('photoDialog').addEventListener('close', () => { state.draft = null; $('imgSlots').replaceChildren(); $('pTitle').value = ''; $('pNotes').value = ''; });
    $('vClose').addEventListener('click', closeViewer);
    $('viewerDialog').addEventListener('close', () => { if (state.viewer) closeViewer(); });
    $('vPrev').addEventListener('click', () => stepViewer(-1));
    $('vNext').addEventListener('click', () => stepViewer(1));
    $('vSave').addEventListener('click', saveViewerCopy);
    $('vEdit').addEventListener('click', () => { const id = state.viewer && state.viewer.docId; if (id) openPhotoEditor(id); });
    $('vDelete').addEventListener('click', () => { const id = state.viewer && state.viewer.docId; if (id) deletePhotoDoc(id); });
    let touchX = null;
    $('vStage').addEventListener('touchstart', (e) => { touchX = e.touches[0].clientX; }, { passive: true });
    $('vStage').addEventListener('touchend', (e) => {
      if (touchX === null) return;
      const dx = e.changedTouches[0].clientX - touchX;
      touchX = null;
      if (Math.abs(dx) > 50) stepViewer(dx < 0 ? 1 : -1);
    }, { passive: true });

    $('editForm').addEventListener('submit', (e) => { e.preventDefault(); saveCredential(false); });
    $('saveNewBtn').addEventListener('click', () => saveCredential(true));
    $('editDialog').querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', closeEditor));
    $('editDialog').addEventListener('close', () => { clearEditForm(); state.editingId = null; });
    $('genBtn').addEventListener('click', () => {
      $('fPass').value = generatePassword(20);
      $('fPass').type = 'text';
      syncRevealButton('fPass');
      toast('Strong password generated');
    });
    $('parseBtn').addEventListener('click', parsePasted);
    $('fUrl').addEventListener('blur', () => {
      if (!$('fName').value.trim() && $('fUrl').value.trim()) $('fName').value = nameFromUrl($('fUrl').value);
    });

    document.addEventListener('keydown', (e) => {
      if (!state.key) return;
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
      if (e.key === 'Escape' && state.expandedId && !$('editDialog').open && !$('askDialog').open) collapse();
      if ($('viewerDialog').open && (e.key === 'ArrowLeft' || e.key === 'ArrowRight')) stepViewer(e.key === 'ArrowLeft' ? -1 : 1);
      if (e.key === '/' && !typing && !$('editDialog').open && !$('photoDialog').open && !$('viewerDialog').open) { e.preventDefault(); $('searchInput').focus(); }
    });
  }

  // =========================================================
  // Start
  // =========================================================
  async function init() {
    hydrateIcons();
    fillCategorySelect();
    fillTypeSelect();
    bindEvents();

    if (!window.crypto || !crypto.subtle || !window.indexedDB) {
      setLockMode('unlock');
      $('unlockBtn').disabled = true;
      lockError('This browser cannot run KEYVAULT securely here. Open it over HTTPS (or localhost) in a modern browser.');
      return;
    }
    let record = null;
    try { record = await dbGet(); } catch { /* storage blocked */ }
    setLockMode(record ? 'unlock' : 'setup');
    showLockScreen();
  }

  init();

  // Offline install support (only works when served over http/https, not from a double-clicked file)
  if ('serviceWorker' in navigator && /^https?:$/.test(location.protocol)) {
    window.addEventListener('load', () => navigator.serviceWorker.register('sw.js').catch(() => {}));
  }
})();
