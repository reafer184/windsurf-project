const API_BASE = `${window.location.origin}/api/v1`;

const state = {
  mode: 'login',
  accessToken: sessionStorage.getItem('access_token') || '',
  refreshToken: localStorage.getItem('refresh_token') || '',
  accounts: [],
  masterPassword: '',
  authSubmitting: false
};

const els = {
  authView: document.getElementById('auth-view'),
  appView: document.getElementById('app-view'),
  authForm: document.getElementById('auth-form'),
  addAccountForm: document.getElementById('add-account-form'),
  accountsList: document.getElementById('accounts-list'),
  status: document.getElementById('status'),
  tabLogin: document.getElementById('tab-login'),
  tabRegister: document.getElementById('tab-register'),
  submit: document.getElementById('auth-submit'),
  displayName: document.getElementById('display-name')
};

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}

const setStatus = (msg, type = 'info') => {
  els.status.textContent = msg;
  els.status.classList.remove('status-error', 'status-success', 'status-loading');
  if (type === 'error') els.status.classList.add('status-error');
  if (type === 'success') els.status.classList.add('status-success');
  if (type === 'loading') els.status.classList.add('status-loading');
};

const setAuthMode = (mode) => {
  state.mode = mode;
  const registerMode = mode === 'register';
  els.tabLogin.classList.toggle('active', !registerMode);
  els.tabRegister.classList.toggle('active', registerMode);
  els.submit.textContent = registerMode ? 'Зарегистрироваться' : 'Войти';
  els.displayName.classList.toggle('hidden', !registerMode);
  els.displayName.required = registerMode;
};

const fetchWithTimeout = async (url, options = {}, timeoutMs = 10000) => {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
};

const api = async (path, options = {}) => {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (state.accessToken) headers.Authorization = `Bearer ${state.accessToken}`;

  let response;
  try {
    response = await fetchWithTimeout(`${API_BASE}${path}`, { ...options, headers });
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new Error('Сервер отвечает слишком долго. Попробуй снова.');
    }
    throw new Error('Нет соединения с сервером. Проверь сеть и попробуй снова.');
  }

  if (response.status === 401 && state.refreshToken) {
    const refreshed = await fetchWithTimeout(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: state.refreshToken })
    });

    if (refreshed.ok) {
      const data = await refreshed.json();
      state.accessToken = data.access_token;
      state.refreshToken = data.refresh_token;
      sessionStorage.setItem('access_token', state.accessToken);
      localStorage.setItem('refresh_token', state.refreshToken);
      headers.Authorization = `Bearer ${state.accessToken}`;
      response = await fetchWithTimeout(`${API_BASE}${path}`, { ...options, headers });
    }
  }

  let data = {};
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    data = await response.json().catch(() => ({}));
  } else {
    const text = await response.text().catch(() => '');
    if (text) data = { message: text };
  }

  if (!response.ok) {
    if (response.status === 429) {
      throw new Error('Слишком много попыток. Подожди немного и попробуй снова.');
    }

    if (response.status >= 500) {
      throw new Error('Ошибка сервера. Попробуй чуть позже.');
    }

    throw new Error(data.message || data.error || `Ошибка запроса (${response.status})`);
  }

  return data;
};

const toBase64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));

const fromBase64 = (base64) => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));

const isCryptoAvailable = () => {
  const webCrypto = globalThis.crypto;
  return Boolean(
    webCrypto
    && typeof webCrypto.getRandomValues === 'function'
    && webCrypto.subtle
    && typeof webCrypto.subtle.importKey === 'function'
    && typeof webCrypto.subtle.encrypt === 'function'
    && typeof webCrypto.subtle.decrypt === 'function'
    && typeof webCrypto.subtle.sign === 'function'
    && window.isSecureContext
  );
};

const simpleHash = (str) => {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).padStart(8, '0');
};

const xorEncrypt = (text, password) => {
  const key = simpleHash(password + 'totp-salt-v1');
  const textBytes = new TextEncoder().encode(text);
  const keyBytes = new TextEncoder().encode(key);
  const result = new Uint8Array(textBytes.length);
  for (let i = 0; i < textBytes.length; i++) {
    result[i] = textBytes[i] ^ keyBytes[i % keyBytes.length];
  }
  return toBase64(result);
};

const xorDecrypt = (encrypted, password) => {
  const key = simpleHash(password + 'totp-salt-v1');
  const encBytes = fromBase64(encrypted);
  const keyBytes = new TextEncoder().encode(key);
  const result = new Uint8Array(encBytes.length);
  for (let i = 0; i < encBytes.length; i++) {
    result[i] = encBytes[i] ^ keyBytes[i % keyBytes.length];
  }
  return new TextDecoder().decode(result);
};

const deriveKey = async (password, salt) => {
  if (!isCryptoAvailable()) {
    throw new Error('WEBCRYPTO_UNAVAILABLE');
  }
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 310000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
};

const encryptSecret = async (secret, password) => {
  if (!isCryptoAvailable()) {
    const encrypted = xorEncrypt(secret, password);
    return { secret_enc: encrypted, iv: 'http-fallback' };
  }
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, 'totp-static-salt-v1');
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(secret));
    return { secret_enc: toBase64(encrypted), iv: toBase64(iv) };
  } catch {
    const encrypted = xorEncrypt(secret, password);
    return { secret_enc: encrypted, iv: 'http-fallback' };
  }
};

const decryptSecret = async (secretEnc, ivB64, password) => {
  if (ivB64 === 'http-fallback') {
    return xorDecrypt(secretEnc, password);
  }
  if (!isCryptoAvailable()) {
    throw new Error('Расшифровать сохранённый секрет можно только через HTTPS. Открой приложение по защищённому адресу.');
  }
  const key = await deriveKey(password, 'totp-static-salt-v1');
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(ivB64) }, key, fromBase64(secretEnc));
  return new TextDecoder().decode(plain);
};

const base32ToBytes = (input) => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.toUpperCase().replace(/=+$/g, '');
  let bits = '';
  for (const ch of clean) {
    const val = alphabet.indexOf(ch);
    if (val < 0) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
};

const sha1 = (bytes) => {
  const rotl = (n, b) => (n << b) | (n >>> (32 - b));
  const words = [];
  for (let i = 0; i < bytes.length; i += 4) {
    words.push((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]);
  }
  const bitLen = bytes.length * 8;
  words[bytes.length >> 2] |= 0x80 << (24 - (bytes.length % 4) * 8);
  words[(((bytes.length + 8) >> 6) << 4) + 15] = bitLen;
  
  let [h0, h1, h2, h3, h4] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
  
  for (let i = 0; i < words.length; i += 16) {
    const w = words.slice(i, i + 16);
    for (let j = 16; j < 80; j++) {
      w[j] = rotl(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
    }
    let [a, b, c, d, e] = [h0, h1, h2, h3, h4];
    for (let j = 0; j < 80; j++) {
      const [f, k] = j < 20 ? [(b & c) | (~b & d), 0x5A827999] :
                     j < 40 ? [b ^ c ^ d, 0x6ED9EBA1] :
                     j < 60 ? [(b & c) | (b & d) | (c & d), 0x8F1BBCDC] :
                              [b ^ c ^ d, 0xCA62C1D6];
      const temp = (rotl(a, 5) + f + e + k + w[j]) >>> 0;
      [e, d, c, b, a] = [d, c, rotl(b, 30), a, temp];
    }
    [h0, h1, h2, h3, h4] = [(h0 + a) >>> 0, (h1 + b) >>> 0, (h2 + c) >>> 0, (h3 + d) >>> 0, (h4 + e) >>> 0];
  }
  
  const result = new Uint8Array(20);
  [h0, h1, h2, h3, h4].forEach((h, i) => {
    result[i * 4] = h >>> 24;
    result[i * 4 + 1] = h >>> 16;
    result[i * 4 + 2] = h >>> 8;
    result[i * 4 + 3] = h;
  });
  return result;
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
  
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = key[i] ^ 0x36;
    opad[i] = key[i] ^ 0x5C;
  }
  ipad.set(message, blockSize);
  
  const innerHash = sha1(ipad);
  opad.set(innerHash, blockSize);
  
  return sha1(opad);
};

const hotp = async (secret, counter) => {
  const keyBytes = base32ToBytes(secret);
  const view = new DataView(new ArrayBuffer(8));
  view.setUint32(4, counter);
  const message = new Uint8Array(view.buffer);
  
  let hmac;
  if (isCryptoAvailable()) {
    try {
      const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
      hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
    } catch {
      hmac = hmacSha1(keyBytes, message);
    }
  } else {
    hmac = hmacSha1(keyBytes, message);
  }
  
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(code % 1000000).padStart(6, '0');
};

const totp = (secret, period = 30) => hotp(secret, Math.floor(Date.now() / 1000 / period));

const getRemainingSeconds = (period) => {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const elapsed = nowSeconds % period;
  return period - elapsed;
};

const renderAccounts = async () => {
  els.accountsList.innerHTML = '';

  for (const account of state.accounts) {
    const li = document.createElement('li');
    const left = document.createElement('div');
    const right = document.createElement('div');
    const title = `${account.issuer}${account.account_name ? ` (${account.account_name})` : ''}`;

    left.innerHTML = `<strong>${title}</strong><div class="muted">${account.algorithm} · ${account.period}s</div>`;

    let code = '••••••';
    let copyDisabled = true;
    const remaining = getRemainingSeconds(account.period);
    const progressPercent = Math.max(0, Math.min(100, (remaining / account.period) * 100));

    if (state.masterPassword) {
      try {
        const secret = await decryptSecret(account.secret_enc, account.iv, state.masterPassword);
        code = await totp(secret, account.period);
        copyDisabled = false;
      } catch {
        code = 'ERR';
      }
    }

    right.innerHTML = `
      <div class="account-right">
        <div class="code">${code}</div>
        <div class="code-meta">
          <span>Обновится через ${remaining}с</span>
          <button class="copy-btn" type="button" data-code="${code}" ${copyDisabled ? 'disabled' : ''}>Копировать</button>
        </div>
        <div class="code-progress"><span style="width:${progressPercent}%"></span></div>
      </div>
    `;
    li.appendChild(left);
    li.appendChild(right);
    els.accountsList.appendChild(li);
  }
};

const loadAccounts = async () => {
  const data = await api('/accounts');
  state.accounts = data.accounts || [];
  await renderAccounts();
};

const showApp = async () => {
  els.authView.classList.add('hidden');
  els.appView.classList.remove('hidden');
  await loadAccounts();
};

const showAuth = () => {
  els.authView.classList.remove('hidden');
  els.appView.classList.add('hidden');
};

els.tabLogin.addEventListener('click', () => {
  setAuthMode('login');
});

els.tabRegister.addEventListener('click', () => {
  setAuthMode('register');
});

els.authForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (state.authSubmitting) return;

  try {
    state.authSubmitting = true;
    els.submit.disabled = true;
    setStatus(state.mode === 'register' ? 'Создаю аккаунт...' : 'Выполняю вход...', 'loading');

    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const displayName = document.getElementById('display-name').value.trim();

    if (state.mode === 'register' && !displayName) {
      throw new Error('Для регистрации укажи имя.');
    }

    const path = state.mode === 'register' ? '/auth/register' : '/auth/login';
    const body = state.mode === 'register'
      ? { email, password, display_name: displayName || undefined }
      : { email, password, device_name: 'PWA Browser' };

    const data = await api(path, { method: 'POST', body: JSON.stringify(body) });
    state.accessToken = data.access_token;
    state.refreshToken = data.refresh_token;
    sessionStorage.setItem('access_token', state.accessToken);
    localStorage.setItem('refresh_token', state.refreshToken);
    setStatus(state.mode === 'register' ? 'Аккаунт создан, вход выполнен' : 'Успешный вход', 'success');
    await showApp();
  } catch (error) {
    setStatus(error.message, 'error');
  } finally {
    state.authSubmitting = false;
    els.submit.disabled = false;
    els.submit.textContent = state.mode === 'register' ? 'Зарегистрироваться' : 'Войти';
  }
});

document.getElementById('logout-btn').addEventListener('click', async () => {
  try {
    await api('/auth/logout', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: state.refreshToken })
    });
  } catch {}

  state.accessToken = '';
  state.refreshToken = '';
  state.masterPassword = '';
  sessionStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  showAuth();
  setStatus('Выход выполнен', 'success');
});

document.getElementById('refresh-btn').addEventListener('click', async () => {
  try {
    await loadAccounts();
    setStatus('Список обновлён', 'success');
  } catch (error) {
    setStatus(error.message, 'error');
  }
});

document.getElementById('unlock-btn').addEventListener('click', async () => {
  const password = prompt('Введите мастер-пароль для расшифровки секретов');
  if (!password) return;
  state.masterPassword = password;
  await renderAccounts();
});

els.accountsList.addEventListener('click', async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (!target.classList.contains('copy-btn')) return;

  const code = target.dataset.code;
  if (!code || code === '••••••' || code === 'ERR') return;

  try {
    await navigator.clipboard.writeText(code);
    setStatus('Код скопирован в буфер', 'success');
  } catch {
    setStatus('Не удалось скопировать код', 'error');
  }
});

els.addAccountForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  try {
    if (!state.masterPassword) {
      throw new Error('Сначала нажми "Разблокировать секреты" и введи мастер-пароль');
    }

    const issuer = document.getElementById('issuer').value.trim();
    const accountName = document.getElementById('account-name').value.trim();
    const secret = document.getElementById('secret').value.trim();

    const encrypted = await encryptSecret(secret, state.masterPassword);

    await api('/accounts', {
      method: 'POST',
      body: JSON.stringify({
        issuer,
        account_name: accountName || undefined,
        secret_enc: encrypted.secret_enc,
        iv: encrypted.iv,
        digits: 6,
        period: 30,
        algorithm: 'SHA1'
      })
    });

    els.addAccountForm.reset();
    await loadAccounts();
    setStatus('Аккаунт добавлен', 'success');
  } catch (error) {
    setStatus(error.message, 'error');
  }
});

setInterval(() => {
  if (!els.appView.classList.contains('hidden')) {
    renderAccounts().catch(() => {});
  }
}, 1000);

if (state.accessToken) {
  showApp().catch(() => showAuth());
} else {
  showAuth();
}

setAuthMode('login');
