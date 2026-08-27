// js/vault.js
import { packVault, unpackVault, deriveVaultKeyWithSecondFactor, wipeBuffer } from './crypto.js';

export class Vault {
  constructor() {
    this.items = {};
    this.categories = [];
    this.vaultKeyRaw = null;
    this.unlocked = false;
    this.lastUpdated = null;
    // Dati del secondo fattore
    this.twoFactor = {
      type: null,          // 'biometric' | 'totp' | null
      biometricSalt: null, // base64
      credentialId: null,  // per WebAuthn
      totpSecret: null     // base32
    };
    this.lastFullPasswordCheck = null; // timestamp ISO
  }

  // ===== CREAZIONE VAULT =====
  async create(masterPassword, twoFactorData = null) {
    // twoFactorData: { type, biometricSalt?, credentialId?, totpSecret? }
    this.items = {};
    this.categories = ['Personale', 'Lavoro', 'Finanza'];
    this.lastUpdated = new Date().toISOString();
    this.lastFullPasswordCheck = new Date().toISOString();

    // Memorizza i dati del secondo fattore
    if (twoFactorData) {
      this.twoFactor.type = twoFactorData.type;
      if (twoFactorData.type === 'biometric') {
        this.twoFactor.biometricSalt = twoFactorData.biometricSalt || null;
        this.twoFactor.credentialId = twoFactorData.credentialId || null;
        this.twoFactor.totpSecret = null;
      } else if (twoFactorData.type === 'totp') {
        this.twoFactor.totpSecret = twoFactorData.totpSecret || null;
        this.twoFactor.biometricSalt = null;
        this.twoFactor.credentialId = null;
      } else {
        this.twoFactor.type = null;
        this.twoFactor.biometricSalt = null;
        this.twoFactor.credentialId = null;
        this.twoFactor.totpSecret = null;
      }
    } else {
      this.twoFactor.type = null;
      this.twoFactor.biometricSalt = null;
      this.twoFactor.credentialId = null;
      this.twoFactor.totpSecret = null;
    }

    // Serializza il vault
    const vaultJson = JSON.stringify({
      items: this.items,
      categories: this.categories,
      lastUpdated: this.lastUpdated,
      twoFactor: this.twoFactor,
      lastFullPasswordCheck: this.lastFullPasswordCheck
    });

    // Pacchettizza usando la password
    const { packed, vaultKeyRaw } = await packVault(masterPassword, vaultJson);
    this.vaultKeyRaw = vaultKeyRaw;
    this.unlocked = true;
    return packed;
  }

  // ===== SBLOCCA VAULT =====
  async unlock(masterPassword, encryptedData) {
    try {
      const { vaultJson, vaultKeyRaw } = await unpackVault(masterPassword, encryptedData);
      const parsed = JSON.parse(vaultJson);
      
      this.items = parsed.items || {};
      this.categories = parsed.categories || [];
      this.lastUpdated = parsed.lastUpdated || new Date().toISOString();
      this.twoFactor = parsed.twoFactor || { type: null, biometricSalt: null, credentialId: null, totpSecret: null };
      this.lastFullPasswordCheck = parsed.lastFullPasswordCheck || null;
      this.vaultKeyRaw = vaultKeyRaw;
      this.unlocked = true;
      return true;
    } catch (e) {
      throw new Error("Password errata o dati corrotti");
    }
  }

  // ===== BLOCCA VAULT =====
  lock() {
    if (this.vaultKeyRaw) {
      wipeBuffer(this.vaultKeyRaw);
      this.vaultKeyRaw = null;
    }
    this.items = {};
    this.categories = [];
    this.unlocked = false;
    // Non cancelliamo i metadati 2FA perché servono per il prossimo sblocco
  }

  isUnlocked() {
    return this.unlocked;
  }

  // ===== GESTIONE ITEM =====
  addItem(itemData) {
    const id = crypto.randomUUID();
    this.items[id] = { id, ...itemData, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    this.lastUpdated = new Date().toISOString();
    return id;
  }

  updateItem(id, changes) {
    if (this.items[id]) {
      this.items[id] = { ...this.items[id], ...changes, updatedAt: new Date().toISOString() };
      this.lastUpdated = new Date().toISOString();
    }
  }

  deleteItem(id) {
    delete this.items[id];
    this.lastUpdated = new Date().toISOString();
  }

  getItem(id) {
    return this.items[id] || null;
  }

  getAllItems() {
    return Object.values(this.items).sort((a, b) => a.name.localeCompare(b.name));
  }

  searchItems(query) {
    const q = query.toLowerCase();
    return this.getAllItems().filter(item =>
      item.name.toLowerCase().includes(q) ||
      (item.username && item.username.toLowerCase().includes(q)) ||
      (item.url && item.url.toLowerCase().includes(q))
    );
  }

  getItemsByCategory(category) {
    return this.getAllItems().filter(item => item.category === category);
  }

  // ===== GESTIONE CATEGORIE =====
  getCategories() {
    return this.categories;
  }

  addCategory(name) {
    if (!this.categories.includes(name)) {
      this.categories.push(name);
      this.lastUpdated = new Date().toISOString();
    }
  }

  deleteCategory(name) {
    this.categories = this.categories.filter(c => c !== name);
    this.lastUpdated = new Date().toISOString();
  }

  // ===== ESPORTAZIONE / IMPORTAZIONE CSV =====
  exportToCSV() {
    let csv = "Nome,Sito web,Nome utente,Password,Note,Categoria\n";
    this.getAllItems().forEach(item => {
      const row = [
        item.name || '',
        item.url || '',
        item.username || '',
        item.password || '',
        item.notes || '',
        item.category || ''
      ].map(v => `"${v.replace(/"/g, '""')}"`).join(',');
      csv += row + "\n";
    });
    return csv;
  }

  importFromCSV(csvString) {
    const lines = csvString.split('\n');
    let count = 0;
    if (lines.length > 1) {
      for (let i = 1; i < lines.length; i++) {
        if (!lines[i].trim()) continue;
        const row = [];
        let inQuotes = false;
        let currentValue = '';
        for (let j = 0; j < lines[i].length; j++) {
          const char = lines[i][j];
          if (char === '"' && lines[i][j+1] === '"') {
            currentValue += '"';
            j++;
          } else if (char === '"') {
            inQuotes = !inQuotes;
          } else if (char === ',' && !inQuotes) {
            row.push(currentValue);
            currentValue = '';
          } else {
            currentValue += char;
          }
        }
        row.push(currentValue);

        if (row.length >= 4) {
          this.addItem({
            name: row[0] || 'Importato',
            url: row[1] || '',
            username: row[2] || '',
            password: row[3] || '',
            notes: row[4] || '',
            category: row[5] || '',
            favorite: false
          });
          count++;
        }
      }
    }
    if (count > 0) this.lastUpdated = new Date().toISOString();
    return count;
  }

  // ===== CRITTOGRAFIA =====
  async getEncryptedData(password) {
    if (!this.unlocked) throw new Error("Vault is locked");
    // Assicuriamoci che i metadati 2FA e lastFullPasswordCheck siano inclusi
    const vaultJson = JSON.stringify({
      items: this.items,
      categories: this.categories,
      lastUpdated: this.lastUpdated,
      twoFactor: this.twoFactor,
      lastFullPasswordCheck: this.lastFullPasswordCheck
    });
    const { packed } = await packVault(password, vaultJson, this.vaultKeyRaw);
    return packed;
  }

  async changeMasterPassword(currentPassword, newPassword) {
    // Verifichiamo che la password corrente sia corretta (decripta e ripristina)
    const vaultJson = JSON.stringify({
      items: this.items,
      categories: this.categories,
      lastUpdated: this.lastUpdated,
      twoFactor: this.twoFactor,
      lastFullPasswordCheck: this.lastFullPasswordCheck
    });
    // Ricripta con la nuova password
    const { packed, vaultKeyRaw } = await packVault(newPassword, vaultJson);
    this.vaultKeyRaw = vaultKeyRaw;
    this.lastFullPasswordCheck = new Date().toISOString();
    return packed;
  }

  // ===== STATISTICHE =====
  getStats() {
    return {
      totalItems: Object.keys(this.items).length,
      categories: this.categories.length,
      lastUpdated: this.lastUpdated,
      twoFactorType: this.twoFactor.type,
      lastFullPasswordCheck: this.lastFullPasswordCheck
    };
  }

  // ===== METODI PER IL SECONDO FATTORE =====
  getTwoFactorConfig() {
    return { ...this.twoFactor };
  }

  setTwoFactorConfig(config) {
    // config: { type, biometricSalt, credentialId, totpSecret }
    this.twoFactor.type = config.type || null;
    this.twoFactor.biometricSalt = config.biometricSalt || null;
    this.twoFactor.credentialId = config.credentialId || null;
    this.twoFactor.totpSecret = config.totpSecret || null;
    this.lastUpdated = new Date().toISOString();
  }

  // Verifica se il secondo fattore è configurato
  hasTwoFactor() {
    return this.twoFactor.type !== null;
  }

  // Aggiorna il timestamp dell'ultimo controllo password completo
  updateLastFullPasswordCheck() {
    this.lastFullPasswordCheck = new Date().toISOString();
    this.lastUpdated = new Date().toISOString();
  }

  // Verifica se è passata più di una settimana dall'ultimo full password check
  isFullPasswordCheckExpired() {
    if (!this.lastFullPasswordCheck) return true;
    const last = new Date(this.lastFullPasswordCheck);
    const sevenDays = 7 * 24 * 60 * 60 * 1000;
    return (Date.now() - last.getTime()) > sevenDays;
  }
}