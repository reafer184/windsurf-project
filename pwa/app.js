import { store } from './db.js';
import { gostEncrypt, gostDecrypt, streebog256 } from './gost.js';

/**
 * Client-only GOST TOTP Authenticator
 * Encryption: GOST R 34.12-2015 Grasshopper CTR + OMAC
 * KDF:        Streebog-256 (GOST R 34.11-2012) x100k
 * TOTP:       RFC 6238 / HMAC-Streebog-256  ← ГОСТ-вариант, совместим с server_gost.py
 * Camera:     @capacitor/camera (iOS/Android native) with getUserMedia fallback (web)
 */

const OTP_ALGORITHM = 'GOST_STREEBOG_256';

const state = {
  masterPassword: sessionStorage.getItem('master_pass') || '',
  isUnlocked: false
};

const els = {
  accountsList:  document.getElementById('accounts-list'),
  status:        document.getElementById('status'),
  unlockBtn:     document.getElementById('unlock-btn'),
  lockBtn:       document.getElementById('lock-btn'),
  addForm:       document.getElementById('add-account-form'),
  qrModal:       document.getElementById('qr-modal'),
  qrVideo:       document.getElementById('qr-video'),
  qrCloseBtn:    document.getElementById('qr-close-btn'),
  scanQrBtn:     document.getElementById('scan-qr-btn'),
  exportBtn:     document.getElementById('export-btn'),
  importBtn:     document.getElementById('import-btn'),
  importFile:    document.getElementById('import-file'),
  lockedView:    document.getElementById('locked-view'),
  unlockedView:  document.getElementById('unlocked-view')
};

let qrStream     = null;
let qrScanFrame  = null;
let updateInterval = null;

// ── Platform detection ─────────────────────────────────────────────────────────
let CapCamera      = null;
let CapBarcodeScanner = null;

const isCapacitorNative = () =>
  typeof window !== 'undefined' &&
  typeof window.Capacitor !== 'undefined' &&
  window.Capacitor.isNativePlatform();

const loadCapacitorPlugins = async () => {
  if (!isCapacitorNative()) return;
  try {
    const mod = await import('./node_modules/@capacitor/camera/dist/esm/index.js');
    CapCamera = mod.Camera;
  } catch {
    // Plugin not bundled yet — will use getUserMedia fallback
  }
};

if ('serviceWorker' in navigator && !isCapacitorNative()) {
  navigator.serviceWorker.register('sw.js')
    .then(reg => console.log('SW registered:', reg.scope))
    .catch(err => console.warn('SW registration failed:', err));
}

const setStatus = (msg, type = 'info') => {
  els.status.textContent = msg;
  els.status.className   = '';
  if (type) els.status.classList.add(`status-${type}`);
};

// ── Base32 ────────────────────────────────────────────────────────────────────
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

// ── HMAC-Streebog-256 ─────────────────────────────────────────────────────────
// Совместим с server_gost.py: gostcrypto.gosthmac.new('HMAC_GOSTR3411_2012_256', secret, msg)
// RFC 2104: HMAC(K, m) = H((K ^ opad) || H((K ^ ipad) || m))
// Размер блока Стрибог = 64 байта
const hmacStreebog256 = (key, message) => {
  const BLOCK_SIZE = 64;
  // Если ключ длиннее блока — хэшируем его
  let k = key.length > BLOCK_SIZE ? streebog256(key) : key;
  // Если короче — дополняем нулями
  if (k.length < BLOCK_SIZE) {
    const padded = new Uint8Array(BLOCK_SIZE);
    padded.set(k);
    k = padded;
  }
  // ipad = 0x36, opad = 0x5C
  const ipad = new Uint8Array(BLOCK_SIZE);
  const opad = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5C;
  }
  // inner = H(ipad || message)
  const innerInput = new Uint8Array(BLOCK_SIZE + message.length);
  innerInput.set(ipad);
  innerInput.set(message, BLOCK_SIZE);
  const innerHash = streebog256(innerInput);
  // outer = H(opad || inner)
  const outerInput = new Uint8Array(BLOCK_SIZE + innerHash.length);
  outerInput.set(opad);
  outerInput.set(innerHash, BLOCK_SIZE);
  return streebog256(outerInput);
};

// ── GOST TOTP (RFC 6238 механика + HMAC-Streebog-256) ─────────────────────────
// Полностью совместим с hotp_gost() из server_gost.py
const hotp = (secret, counter) => {
  const kv = base32ToBytes(secret);
  // counter → 8 байт big-endian (struct.pack(">Q", counter) в Python)
  const dv = new DataView(new ArrayBuffer(8));
  dv.setUint32(0, Math.floor(counter / 0x100000000), false); // старшие 4 байта
  dv.setUint32(4, counter >>> 0, false);                     // младшие 4 байта
  const msg  = new Uint8Array(dv.buffer);
  const hmac = hmacStreebog256(kv, msg);
  // Dynamic truncation по RFC 4226: offset = hmac[-1] & 0x0F
  const off  = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[off] & 0x7f) << 24) |
               ((hmac[off + 1] & 0xff) << 16) |
               ((hmac[off + 2] & 0xff) << 8)  |
               (hmac[off + 3] & 0xff);
  return String(code % 1000000).padStart(6, '0');
};

const totp = (secret, period = 30) => hotp(secret, Math.floor(Date.now() / 1000 / period));
const getRemainingSeconds = (period) => period - (Math.floor(Date.now() / 1000) % period);

// ── GOST encrypt / decrypt secrets ────────────────────────────────────────────
const encryptSecret = async (secret, password) => {
  setStatus('Шифрование ГОСТ...', 'info');
  const result = await gostEncrypt(secret, password);
  setStatus('');
  return result;
};

const decryptSecret = async (account, password) => {
  if (account.algo === 'GOST-R-34.12-2015')
    return gostDecrypt(account.secretEnc, account.iv, account.mac, password);
  // Legacy XOR fallback
  const key = (() => {
    let hash = 0; const str = password + 'totp-salt-v1';
    for (let i = 0; i < str.length; i++) { hash = ((hash << 5) - hash) + str.charCodeAt(i); hash = hash & hash; }
    return Math.abs(hash).toString(16).padStart(16, '0');
  })();
  const fromB64 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const eb = fromB64(account.secretEnc), kb = new TextEncoder().encode(key);
  const r = new Uint8Array(eb.length);
  for (let i = 0; i < eb.length; i++) r[i] = eb[i] ^ kb[i % kb.length];
  return new TextDecoder().decode(r);
};

// ── QR parsing ─────────────────────────────────────────────────────────────────
const parseOtpAuthUri = (raw) => {
  if (!raw || typeof raw !== 'string') throw new Error('QR-код пустой');
  const value = raw.trim();
  if (!value.toLowerCase().startsWith('otpauth://')) throw new Error('Поддерживаются только QR-коды otpauth://');
  const url = new URL(value);
  if (url.protocol !== 'otpauth:' || url.hostname.toLowerCase() !== 'totp')
    throw new Error('Поддерживаются только TOTP QR-коды');
  const label  = decodeURIComponent(url.pathname.replace(/^\//, ''));
  const [li = '', ...rest] = label.split(':');
  const secret = (url.searchParams.get('secret') || '').replace(/\s+/g, '').toUpperCase();
  if (!secret) throw new Error('В QR-коде отсутствует секрет');
  // Принимаем algorithm=GOST_STREEBOG_256 (от server_gost.py) и SHA1 (стандартный)
  const algorithm = (url.searchParams.get('algorithm') || 'GOST_STREEBOG_256').toUpperCase();
  return {
    issuer:      (url.searchParams.get('issuer') || li || '').trim(),
    accountName: (rest.join(':').trim() || label || '').trim(),
    secret,
    period:    parseInt(url.searchParams.get('period'))  || 30,
    digits:    parseInt(url.searchParams.get('digits'))  || 6,
    algorithm
  };
};

const fillFormFromParsed = (parsed) => {
  document.getElementById('issuer').value       = parsed.issuer;
  document.getElementById('account-name').value = parsed.accountName;
  document.getElementById('secret').value       = parsed.secret;
  setStatus(`QR-код распознан (алгоритм: ${parsed.algorithm})`, 'success');
};

// ── QR Scanner ─────────────────────────────────────────────────────────────────
const scanQrNative = async () => {
  if (!CapCamera) {
    setStatus('Нативная камера недоступна, перехожу на веб-режим', 'info');
    return false;
  }
  try {
    const { Camera: CameraResultType, CameraSource } = await import('./node_modules/@capacitor/camera/dist/esm/definitions.js');
    const photo = await CapCamera.getPhoto({
      quality:      90,
      allowEditing: false,
      resultType:   'base64',
      source:       CameraSource?.Camera ?? 'CAMERA'
    });
    const base64 = photo.base64String;
    if (!base64) throw new Error('Камера не вернула фото');
    const imgEl = new Image();
    await new Promise((resolve, reject) => {
      imgEl.onload = resolve;
      imgEl.onerror = reject;
      imgEl.src = `data:image/jpeg;base64,${base64}`;
    });
    if (typeof BarcodeDetector !== 'undefined') {
      const detector = new BarcodeDetector({ formats: ['qr_code'] });
      const codes = await detector.detect(imgEl);
      if (codes.length > 0) {
        fillFormFromParsed(parseOtpAuthUri(codes[0].rawValue));
        return true;
      }
      throw new Error('Не удалось распознать QR-код на фото');
    }
    throw new Error('Для распознавания QR установите приложение через npx cap sync');
  } catch (e) {
    setStatus(e.message, 'error');
    return false;
  }
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
    setStatus('Сканирование QR не поддерживается в этом браузере — введите секрет вручную', 'error');
    stopQrScanner();
    return;
  }
  const detector = new BarcodeDetector({ formats: ['qr_code'] });
  const tick = async () => {
    if (!els.qrVideo || els.qrVideo.readyState < 2) { qrScanFrame = requestAnimationFrame(tick); return; }
    try {
      const codes = await detector.detect(els.qrVideo);
      if (codes.length > 0 && codes[0].rawValue) {
        fillFormFromParsed(parseOtpAuthUri(codes[0].rawValue));
        stopQrScanner();
        return;
      }
    } catch (e) { setStatus(e.message, 'error'); stopQrScanner(); return; }
    qrScanFrame = requestAnimationFrame(tick);
  };
  qrScanFrame = requestAnimationFrame(tick);
};

const openQrScanner = async () => {
  if (isCapacitorNative()) {
    await scanQrNative();
    return;
  }
  if (!navigator.mediaDevices?.getUserMedia) {
    setStatus('Камера недоступна — откройте сайт по HTTPS', 'error');
    return;
  }
  try {
    qrStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
    els.qrVideo.srcObject = qrStream;
    await els.qrVideo.play();
    els.qrModal.classList.remove('hidden');
    els.qrModal.setAttribute('aria-hidden', 'false');
    startQrScanLoop();
  } catch { setStatus('Не удалось открыть камеру', 'error'); }
};

// ── UI rendering ──────────────────────────────────────────────────────────────
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
      li.className  = 'account-item';
      li.dataset.id = account.id;
      const remaining       = getRemainingSeconds(account.period || 30);
      const progressPercent = (remaining / (account.period || 30)) * 100;
      let code = '••••••';
      try { code = totp(await decryptSecret(account, state.masterPassword), account.period || 30); } catch { code = 'ERR'; }
      li.innerHTML = `
        <div class="account-info">
          <div class="issuer">${account.issuer || 'Unknown'}</div>
          <div class="account-name">${account.accountName || ''}</div>
          <div class="account-algo">🔐 HMAC-Стрибог-256 (ГОСТ Р 34.11-2012)</div>
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
    const items = els.accountsList.querySelectorAll('.account-item');
    for (let idx = 0; idx < accounts.length; idx++) {
      const account = accounts[idx], li = items[idx];
      if (!li) continue;
      const remaining       = getRemainingSeconds(account.period || 30);
      const progressPercent = (remaining / (account.period || 30)) * 100;
      let code = '••••••';
      try { code = totp(await decryptSecret(account, state.masterPassword), account.period || 30); } catch { code = 'ERR'; }
      const ce = li.querySelector('[data-code-el]'), te = li.querySelector('[data-timer-el]');
      const pe = li.querySelector('.progress'),    cb = li.querySelector('.btn-copy');
      if (ce) ce.textContent = code;
      if (te) te.textContent = `${remaining}s`;
      if (pe) pe.style.width = `${progressPercent}%`;
      if (cb) cb.dataset.code = code;
    }
  }
};

// ── Event handlers ────────────────────────────────────────────────────────────
const unlockApp = () => {
  const pass = prompt('Введите мастер-пароль:');
  if (!pass) return;
  state.masterPassword = pass;
  state.isUnlocked     = true;
  sessionStorage.setItem('master_pass', pass);
  els.lockedView.classList.add('hidden');
  els.unlockedView.classList.remove('hidden');
  renderAccounts(true);
  setStatus('Разблокировано', 'success');
};

const lockApp = () => {
  state.masterPassword = '';
  state.isUnlocked     = false;
  sessionStorage.removeItem('master_pass');
  els.lockedView.classList.remove('hidden');
  els.unlockedView.classList.add('hidden');
  renderAccounts(true);
  setStatus('Заблокировано');
};

const exportAccounts = async () => {
  const data = await store.exportAll();
  const blob = new Blob([data], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `totp-backup-gost-${new Date().toISOString().split('T')[0]}.json`;
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
  } catch (e) { setStatus('Ошибка импорта: ' + e.message, 'error'); }
};

// ── Init ──────────────────────────────────────────────────────────────────────
const init = async () => {
  await loadCapacitorPlugins();
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
    const issuer      = document.getElementById('issuer').value.trim();
    const accountName = document.getElementById('account-name').value.trim();
    const secret      = document.getElementById('secret').value.trim().toUpperCase();
    if (!issuer || !secret) { setStatus('Заполните обязательные поля', 'error'); return; }
    try {
      base32ToBytes(secret);
      const { ciphertext, iv, mac, algo } = await encryptSecret(secret, state.masterPassword);
      await store.addAccount({
        issuer, accountName,
        secretEnc: ciphertext, iv, mac, algo,
        digits: 6, period: 30,
        algorithm: OTP_ALGORITHM
      });
      els.addForm.reset();
      await renderAccounts(true);
      setStatus('Аккаунт добавлен (HMAC-Стрибог-256)', 'success');
    } catch (e) { setStatus('Ошибка: ' + e.message, 'error'); }
  });

  els.accountsList?.addEventListener('click', async (e) => {
    if (e.target.classList.contains('btn-copy')) {
      const code = e.target.dataset.code;
      if (code && code !== '••••••' && code !== 'ERR') {
        try { await navigator.clipboard.writeText(code); setStatus('Код скопирован', 'success'); }
        catch { setStatus('Не удалось скопировать', 'error'); }
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

  updateInterval = setInterval(() => {
    if (state.isUnlocked) renderAccounts(false);
  }, 1000);
};

init().catch(e => {
  console.error('Init failed:', e);
  setStatus('Ошибка инициализации: ' + e.message, 'error');
});
