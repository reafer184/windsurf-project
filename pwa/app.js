import { store } from './db.js';

/**
 * Client-only TOTP Authenticator
 * No server required - works entirely in browser
 * Compatible with Google Authenticator / RFC 6238
 */

const state = {
  masterPassword: sessionStorage.getItem('master_pass') || '',
  accounts: [],
  isUnlocked: false
};

const els = {
  accountsList: document.getElementById('accounts-list'),
  status: document.getElementById('status'),
  unlockBtn: document.getElementById('unlock-btn'),
  lockBtn: document.getElementById('lock-btn'),
  addForm: document.getElementById('add-account-form'),
  qrModal: document.getElementById('qr-modal'),
  qrVideo: document.getElementById('qr-video'),
  qrCloseBtn: document.getElementById('qr-close-btn'),
  scanQrBtn: document.getElementById('scan-qr-btn'),
  exportBtn: document.getElementById('export-btn'),
  importBtn: document.getElementById('import-btn'),
  importFile: document.getElementById('import-file'),
  lockedView: document.getElementById('locked-view'),
  unlockedView: document.getElementById('unlocked-view')
};

let qrStream = null;
let qrScanFrame = null;
let updateInterval = null;

// Service Worker registration for offline support
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js')
    .then(reg => console.log('SW registered:', reg.scope))
    .catch(err => console.log('SW registration failed:', err));
}

// Status display
const setStatus = (msg, type = 'info') => {
  els.status.textContent = msg;
  els.status.className = '';
  if (type) els.status.classList.add(`status-${type}`);
};

// ── Crypto helpers (Web Crypto API: PBKDF2 + AES-GCM) ──────────────────────
const toBase64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const fromBase64 = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

const isCryptoAvailable = () =>
  Boolean(
    globalThis.crypto?.subtle &&
    typeof globalThis.crypto.getRandomValues === 'function' &&
    window.isSecureContext
  );

// Fallback: simple XOR for non-HTTPS environments (e.g. local file://)
const _xorDeriveKey = (password) => {
  let hash = 0;
  const str = password + 'totp-salt-v1';
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).padStart(16, '0');
};

const _xorEncrypt = (text, password) => {
  const key = _xorDeriveKey(password);
  const tb = new TextEncoder().encode(text);
  const kb = new TextEncoder().encode(key);
  const r = new Uint8Array(tb.length);
  for (let i = 0; i < tb.length; i++) r[i] = tb[i] ^ kb[i % kb.length];
  return toBase64(r);
};

const _xorDecrypt = (encrypted, password) => {
  const key = _xorDeriveKey(password);
  const eb = fromBase64(encrypted);
  const kb = new TextEncoder().encode(key);
  const r = new Uint8Array(eb.length);
  for (let i = 0; i < eb.length; i++) r[i] = eb[i] ^ kb[i % kb.length];
  return new TextDecoder().decode(r);
};

const _pbkdf2Key = async (password) => {
  const enc = new TextEncoder();
  const raw = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode('totp-static-salt-v2'), iterations: 310000, hash: 'SHA-256' },
    raw,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
};

const encrypt = async (text, password) => {
  if (!isCryptoAvailable()) {
    return { ciphertext: _xorEncrypt(text, password), iv: 'xor-fallback' };
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await _pbkdf2Key(password);
  const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
  return { ciphertext: toBase64(enc), iv: toBase64(iv) };
};

const decrypt = async (ciphertext, iv, password) => {
  if (iv === 'xor-fallback') return _xorDecrypt(ciphertext, password);
  if (!isCryptoAvailable()) throw new Error('Расшифровка требует HTTPS. Откройте приложение по защищённому адресу.');
  const key = await _pbkdf2Key(password);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(iv) }, key, fromBase64(ciphertext));
  return new TextDecoder().decode(plain);
};

// ── Base32 / TOTP ───────────────────────────────────────────────────────────
const base32ToBytes = (input) => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.toUpperCase().replace(/=+$/g, '').replace(/\s/g, '');
  let bits = '';
  for (const ch of clean) {
    const val = alphabet.indexOf(ch);
    if (val < 0) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8)
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(bytes);
};

const sha1 = (bytes) => {
  const rotl = (n, b) => ((n << b) | (n >>> (32 - b))) >>> 0;
  const bitLen = bytes.length * 8;
  const totalLen = (((bytes.length + 9 + 63) >> 6) << 6);
  const padded = new Uint8Array(totalLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(totalLen - 4, bitLen >>> 0, false);
  let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
  for (let offset = 0; offset < totalLen; offset += 64) {
    const w = new Uint32Array(80);
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4, false);
    for (let i = 16; i < 80; i++) w[i] = rotl((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]) >>> 0, 1);
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20)      { f = (b & c) | (~b & d); k = 0x5A827999; }
      else if (i < 40) { f = b ^ c ^ d;           k = 0x6ED9EBA1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
      else             { f = b ^ c ^ d;           k = 0xCA62C1D6; }
      const temp = (rotl(a, 5) + (f >>> 0) + e + k + w[i]) >>> 0;
      e = d; d = c; c = rotl(b, 30); b = a; a = temp;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
  }
  const out = new Uint8Array(20);
  const ov = new DataView(out.buffer);
  ov.setUint32(0, h0, false); ov.setUint32(4, h1, false);
  ov.setUint32(8, h2, false); ov.setUint32(12, h3, false); ov.setUint32(16, h4, false);
  return out;
};

const hmacSha1 = (key, message) => {
  const blockSize = 64;
  if (key.length > blockSize) key = sha1(key);
  if (key.length < blockSize) {
    const padded = new Uint8Array(blockSize);
    padded.set(key);
    key = padded;
  }
  const ipad = new Uint8Array(blockSize + message.length);
  const opad = new Uint8Array(blockSize + 20);
  for (let i = 0; i < blockSize; i++) { ipad[i] = key[i] ^ 0x36; opad[i] = key[i] ^ 0x5C; }
  ipad.set(message, blockSize);
  const innerHash = sha1(ipad);
  opad.set(innerHash, blockSize);
  return sha1(opad);
};

const hotp = (secret, counter) => {
  const keyBytes = base32ToBytes(secret);
  const view = new DataView(new ArrayBuffer(8));
  view.setUint32(4, counter);
  const message = new Uint8Array(view.buffer);
  const hmac = hmacSha1(keyBytes, message);
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset+1] & 0xff) << 16) |
               ((hmac[offset+2] & 0xff) << 8)  |  (hmac[offset+3] & 0xff);
  return String(code % 1000000).padStart(6, '0');
};

const totp = (secret, period = 30) => hotp(secret, Math.floor(Date.now() / 1000 / period));
const getRemainingSeconds = (period) => period - (Math.floor(Date.now() / 1000) % period);

// ── QR Scanner ──────────────────────────────────────────────────────────────
const parseOtpAuthUri = (raw) => {
  if (!raw || typeof raw !== 'string') throw new Error('QR-код пустой');
  const value = raw.trim();
  if (!value.toLowerCase().startsWith('otpauth://')) throw new Error('Поддерживаются только QR-коды формата otpauth://');
  const url = new URL(value);
  if (url.protocol !== 'otpauth:' || url.hostname.toLowerCase() !== 'totp') throw new Error('Поддерживаются только TOTP QR-коды');
  const label = decodeURIComponent(url.pathname.replace(/^\//, ''));
  const [labelIssuer = '', ...rest] = label.split(':');
  const labelAccount = rest.join(':').trim();
  const secret = (url.searchParams.get('secret') || '').replace(/\s+/g, '').toUpperCase();
  if (!secret) throw new Error('В QR-коде отсутствует секрет');
  return {
    issuer: (url.searchParams.get('issuer') || labelIssuer || '').trim(),
    accountName: (labelAccount || label || '').trim(),
    secret,
    period: parseInt(url.searchParams.get('period')) || 30,
    digits: parseInt(url.searchParams.get('digits')) || 6,
    algorithm: (url.searchParams.get('algorithm') || 'SHA1').toUpperCase()
  };
};

const stopQrScanner = () => {
  if (qrScanFrame) { cancelAnimationFrame(qrScanFrame); qrScanFrame = null; }
  if (qrStream) { qrStream.getTracks().forEach(t => t.stop()); qrStream = null; }
  if (els.qrVideo) els.qrVideo.srcObject = null;
  if (els.qrModal) {
    els.qrModal.classList.add('hidden');
    els.qrModal.setAttribute('aria-hidden', 'true');
  }
};

const startQrScanLoop = async () => {
  if (typeof BarcodeDetector === 'undefined') {
    setStatus('Сканирование QR не поддерживается в этом браузере', 'error');
    return;
  }
  const detector = new BarcodeDetector({ formats: ['qr_code'] });
  const tick = async () => {
    if (!els.qrVideo || els.qrVideo.readyState < 2) {
      qrScanFrame = requestAnimationFrame(tick);
      return;
    }
    try {
      const codes = await detector.detect(els.qrVideo);
      if (codes.length > 0 && codes[0].rawValue) {
        const parsed = parseOtpAuthUri(codes[0].rawValue);
        document.getElementById('issuer').value = parsed.issuer;
        document.getElementById('account-name').value = parsed.accountName;
        document.getElementById('secret').value = parsed.secret;
        stopQrScanner();
        setStatus('QR-код распознан', 'success');
        return;
      }
    } catch (e) {
      setStatus(e.message, 'error');
      stopQrScanner();
      return;
    }
    qrScanFrame = requestAnimationFrame(tick);
  };
  qrScanFrame = requestAnimationFrame(tick);
};

// ── UI rendering ────────────────────────────────────────────────────────────
// Only re-render code values & progress bars each tick, not entire DOM
const renderAccounts = async (fullRender = true) => {
  if (!state.isUnlocked) {
    els.accountsList.innerHTML = '<p class="locked-hint">🔒 Нажмите "Разблокировать" для просмотра кодов</p>';
    return;
  }

  const accounts = await store.getAllAccounts();
  accounts.sort((a, b) => (a.sortOrder || 0) - (b.sortOrder || 0));

  if (fullRender || els.accountsList.children.length !== accounts.length) {
    els.accountsList.innerHTML = '';
    for (const account of accounts) {
      const li = document.createElement('li');
      li.className = 'account-item';
      li.dataset.id = account.id;

      const remaining = getRemainingSeconds(account.period || 30);
      const progressPercent = (remaining / (account.period || 30)) * 100;

      let code = '••••••';
      try {
        const secret = await decrypt(account.secretEnc, account.iv || 'xor-fallback', state.masterPassword);
        code = totp(secret, account.period || 30);
      } catch { code = 'ERR'; }

      li.innerHTML = `
        <div class="account-info">
          <div class="issuer">${account.issuer || 'Unknown'}</div>
          <div class="account-name">${account.accountName || ''}</div>
        </div>
        <div class="code-section">
          <div class="totp-code" data-code-el>${code}</div>
          <div class="progress-bar"><div class="progress" style="width:${progressPercent}%"></div></div>
          <div class="code-meta" data-timer-el>${remaining}s</div>
        </div>
        <div class="account-actions">
          <button class="btn-copy" data-code="${code}">Копировать</button>
          <button class="btn-delete" data-id="${account.id}">×</button>
        </div>
      `;
      els.accountsList.appendChild(li);
    }
  } else {
    // Fast path: only update codes and timers in-place
    const items = els.accountsList.querySelectorAll('.account-item');
    for (let idx = 0; idx < accounts.length; idx++) {
      const account = accounts[idx];
      const li = items[idx];
      if (!li) continue;
      const remaining = getRemainingSeconds(account.period || 30);
      const progressPercent = (remaining / (account.period || 30)) * 100;
      let code = '••••••';
      try {
        const secret = await decrypt(account.secretEnc, account.iv || 'xor-fallback', state.masterPassword);
        code = totp(secret, account.period || 30);
      } catch { code = 'ERR'; }
      const codeEl = li.querySelector('[data-code-el]');
      const timerEl = li.querySelector('[data-timer-el]');
      const progressEl = li.querySelector('.progress');
      const copyBtn = li.querySelector('.btn-copy');
      if (codeEl) codeEl.textContent = code;
      if (timerEl) timerEl.textContent = `${remaining}s`;
      if (progressEl) progressEl.style.width = `${progressPercent}%`;
      if (copyBtn) copyBtn.dataset.code = code;
    }
  }
};

// ── Event handlers ──────────────────────────────────────────────────────────
const unlockApp = () => {
  const pass = prompt('Введите мастер-пароль:');
  if (!pass) return;
  state.masterPassword = pass;
  state.isUnlocked = true;
  sessionStorage.setItem('master_pass', pass);
  els.lockedView.classList.add('hidden');
  els.unlockedView.classList.remove('hidden');
  renderAccounts(true);
  setStatus('Разблокировано', 'success');
};

const lockApp = () => {
  state.masterPassword = '';
  state.isUnlocked = false;
  sessionStorage.removeItem('master_pass');
  els.lockedView.classList.remove('hidden');
  els.unlockedView.classList.add('hidden');
  renderAccounts(true);
  setStatus('Заблокировано');
};

const openQrScanner = async () => {
  if (!navigator.mediaDevices?.getUserMedia) { setStatus('Камера недоступна', 'error'); return; }
  try {
    qrStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
    els.qrVideo.srcObject = qrStream;
    await els.qrVideo.play();
    els.qrModal.classList.remove('hidden');
    els.qrModal.setAttribute('aria-hidden', 'false');
    startQrScanLoop();
  } catch { setStatus('Не удалось открыть камеру', 'error'); }
};

const exportAccounts = async () => {
  const data = await store.exportAll();
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `totp-backup-${new Date().toISOString().split('T')[0]}.json`;
  a.click();
  URL.revokeObjectURL(url);
  setStatus('Экспорт выполнен', 'success');
};

const importAccounts = async (file) => {
  try {
    const text = await file.text();
    await store.importAll(text);
    await renderAccounts(true);
    setStatus('Импорт выполнен', 'success');
  } catch (e) {
    setStatus('Ошибка импорта: ' + e.message, 'error');
  }
};

// ── Init ────────────────────────────────────────────────────────────────────
const init = async () => {
  await store.init();

  if (state.masterPassword) {
    state.isUnlocked = true;
    els.lockedView.classList.add('hidden');
    els.unlockedView.classList.remove('hidden');
  }

  await renderAccounts(true);

  els.unlockBtn?.addEventListener('click', unlockApp);
  els.lockBtn?.addEventListener('click', lockApp);
  els.scanQrBtn?.addEventListener('click', openQrScanner);
  els.qrCloseBtn?.addEventListener('click', stopQrScanner);
  els.exportBtn?.addEventListener('click', exportAccounts);
  els.importBtn?.addEventListener('click', () => els.importFile?.click());
  els.importFile?.addEventListener('change', (e) => {
    if (e.target.files?.[0]) importAccounts(e.target.files[0]);
  });

  els.addForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!state.isUnlocked) { setStatus('Сначала разблокируйте приложение', 'error'); return; }
    const issuer = document.getElementById('issuer').value.trim();
    const accountName = document.getElementById('account-name').value.trim();
    const secret = document.getElementById('secret').value.trim().toUpperCase();
    if (!issuer || !secret) { setStatus('Заполните обязательные поля', 'error'); return; }
    try {
      base32ToBytes(secret); // validate
      const { ciphertext, iv } = await encrypt(secret, state.masterPassword);
      await store.addAccount({ issuer, accountName, secretEnc: ciphertext, iv, digits: 6, period: 30, algorithm: 'SHA1' });
      els.addForm.reset();
      await renderAccounts(true);
      setStatus('Аккаунт добавлен', 'success');
    } catch (e) {
      setStatus('Ошибка: ' + e.message, 'error');
    }
  });

  els.accountsList?.addEventListener('click', async (e) => {
    if (e.target.classList.contains('btn-copy')) {
      const code = e.target.dataset.code;
      if (code && code !== '••••••' && code !== 'ERR') {
        try {
          await navigator.clipboard.writeText(code);
          setStatus('Код скопирован', 'success');
        } catch { setStatus('Не удалось скопировать', 'error'); }
      }
    }
    if (e.target.classList.contains('btn-delete')) {
      const id = parseInt(e.target.dataset.id);
      if (confirm('Удалить этот аккаунт?')) {
        await store.deleteAccount(id);
        await renderAccounts(true);
        setStatus('Аккаунт удалён', 'success');
      }
    }
  });

  // Tick every second — fast path only updates text/progress, not DOM
  updateInterval = setInterval(() => {
    if (state.isUnlocked) renderAccounts(false);
  }, 1000);
};

init().catch(e => {
  console.error('Init failed:', e);
  setStatus('Ошибка инициализации: ' + e.message, 'error');
});
