const API_BASE = `${window.location.origin}/api/v1`;

const state = {
  mode: 'login',
  accessToken: sessionStorage.getItem('access_token') || '',
  refreshToken: localStorage.getItem('refresh_token') || '',
  accounts: [],
  masterPassword: ''
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
  submit: document.getElementById('auth-submit')
};

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}

const setStatus = (msg) => {
  els.status.textContent = msg;
};

const api = async (path, options = {}) => {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (state.accessToken) headers.Authorization = `Bearer ${state.accessToken}`;

  let response = await fetch(`${API_BASE}${path}`, { ...options, headers });

  if (response.status === 401 && state.refreshToken) {
    const refreshed = await fetch(`${API_BASE}/auth/refresh`, {
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
      response = await fetch(`${API_BASE}${path}`, { ...options, headers });
    }
  }

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.message || data.error || 'Ошибка запроса');
  }

  return data;
};

const toBase64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));

const fromBase64 = (base64) => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));

const deriveKey = async (password, salt) => {
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
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, 'totp-static-salt-v1');
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(secret));
  return { secret_enc: toBase64(encrypted), iv: toBase64(iv) };
};

const decryptSecret = async (secretEnc, ivB64, password) => {
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

const hotp = async (secret, counter) => {
  const key = await crypto.subtle.importKey('raw', base32ToBytes(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const view = new DataView(new ArrayBuffer(8));
  view.setUint32(4, counter);
  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, view.buffer));
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(code % 1000000).padStart(6, '0');
};

const totp = (secret, period = 30) => hotp(secret, Math.floor(Date.now() / 1000 / period));

const renderAccounts = async () => {
  els.accountsList.innerHTML = '';

  for (const account of state.accounts) {
    const li = document.createElement('li');
    const left = document.createElement('div');
    const right = document.createElement('div');
    const title = `${account.issuer}${account.account_name ? ` (${account.account_name})` : ''}`;

    left.innerHTML = `<strong>${title}</strong><div class="muted">${account.algorithm} · ${account.period}s</div>`;

    let code = '••••••';
    if (state.masterPassword) {
      try {
        const secret = await decryptSecret(account.secret_enc, account.iv, state.masterPassword);
        code = await totp(secret, account.period);
      } catch {
        code = 'ERR';
      }
    }

    right.innerHTML = `<div class="code">${code}</div>`;
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
  state.mode = 'login';
  els.tabLogin.classList.add('active');
  els.tabRegister.classList.remove('active');
  els.submit.textContent = 'Войти';
});

els.tabRegister.addEventListener('click', () => {
  state.mode = 'register';
  els.tabRegister.classList.add('active');
  els.tabLogin.classList.remove('active');
  els.submit.textContent = 'Зарегистрироваться';
});

els.authForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  try {
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const displayName = document.getElementById('display-name').value.trim();

    const path = state.mode === 'register' ? '/auth/register' : '/auth/login';
    const body = state.mode === 'register'
      ? { email, password, display_name: displayName || undefined }
      : { email, password, device_name: 'PWA Browser' };

    const data = await api(path, { method: 'POST', body: JSON.stringify(body) });
    state.accessToken = data.access_token;
    state.refreshToken = data.refresh_token;
    sessionStorage.setItem('access_token', state.accessToken);
    localStorage.setItem('refresh_token', state.refreshToken);
    setStatus('Успешный вход');
    await showApp();
  } catch (error) {
    setStatus(error.message);
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
  setStatus('Выход выполнен');
});

document.getElementById('refresh-btn').addEventListener('click', async () => {
  try {
    await loadAccounts();
    setStatus('Список обновлен');
  } catch (error) {
    setStatus(error.message);
  }
});

document.getElementById('unlock-btn').addEventListener('click', async () => {
  const password = prompt('Введите мастер-пароль для расшифровки секретов');
  if (!password) return;
  state.masterPassword = password;
  await renderAccounts();
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
    setStatus('Аккаунт добавлен');
  } catch (error) {
    setStatus(error.message);
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
