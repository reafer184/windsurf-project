/**
 * IndexedDB storage for TOTP secrets
 * Client-only, no server communication
 */

const DB_NAME = 'totp-authenticator';
const DB_VERSION = 1;
const STORE_NAME = 'accounts';
const META_STORE = 'meta';

export class TOTPStore {
  constructor() {
    this.db = null;
  }

  async init() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this.db = request.result;
        resolve(this.db);
      };

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        
        // Store for TOTP accounts
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          const store = db.createObjectStore(STORE_NAME, { keyPath: 'id', autoIncrement: true });
          store.createIndex('issuer', 'issuer', { unique: false });
          store.createIndex('accountName', 'accountName', { unique: false });
        }

        // Store for app metadata (encryption salt, etc)
        if (!db.objectStoreNames.contains(META_STORE)) {
          db.createObjectStore(META_STORE, { keyPath: 'key' });
        }
      };
    });
  }

  async getAllAccounts() {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([STORE_NAME], 'readonly');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.getAll();

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async addAccount(account) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      
      const data = {
        ...account,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      const request = store.add(data);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async updateAccount(id, updates) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      
      const request = store.get(id);
      request.onsuccess = () => {
        const data = { ...request.result, ...updates, updatedAt: new Date().toISOString() };
        const updateRequest = store.put(data);
        updateRequest.onsuccess = () => resolve(updateRequest.result);
        updateRequest.onerror = () => reject(updateRequest.error);
      };
      request.onerror = () => reject(request.error);
    });
  }

  async deleteAccount(id) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.delete(id);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async reorderAccounts(orderedIds) {
    const accounts = await this.getAllAccounts();
    const updates = orderedIds.map((id, index) => this.updateAccount(id, { sortOrder: index }));
    return Promise.all(updates);
  }

  async exportAll() {
    const accounts = await this.getAllAccounts();
    return JSON.stringify(accounts, null, 2);
  }

  async importAll(jsonString) {
    const accounts = JSON.parse(jsonString);
    const transaction = this.db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);

    // Clear existing
    await new Promise((resolve, reject) => {
      const clearRequest = store.clear();
      clearRequest.onsuccess = resolve;
      clearRequest.onerror = () => reject(clearRequest.error);
    });

    // Add imported accounts
    const promises = accounts.map(account => {
      delete account.id; // Let DB generate new IDs
      return new Promise((resolve, reject) => {
        const request = store.add(account);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
    });

    return Promise.all(promises);
  }

  async setMeta(key, value) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([META_STORE], 'readwrite');
      const store = transaction.objectStore(META_STORE);
      const request = store.put({ key, value });

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async getMeta(key) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([META_STORE], 'readonly');
      const store = transaction.objectStore(META_STORE);
      const request = store.get(key);

      request.onsuccess = () => resolve(request.result?.value);
      request.onerror = () => reject(request.error);
    });
  }
}

export const store = new TOTPStore();
