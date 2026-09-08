import { packVault, packVault2SKD, unpackVault, unpackVaultWithKey, repackVaultData, wipeBuffer, unwrapVaultKeyWithPassword, generateSecretKeyRaw, formatSecretKey, isSecretKeyRequired, parseSecretKey } from './crypto_Claude_2FA.js';

export { isSecretKeyRequired, parseSecretKey } from './crypto_Claude_2FA.js';

// Verifica SOLO che la password (ed eventualmente la Secret Key, se il vault la richiede) sia
// corretta e restituisce la vaultKey grezza, SENZA decifrare né esporre il contenuto del vault
// (items/categorie restano cifrati). Pensata per i casi in cui serve confermare le credenziali
// prima di una verifica aggiuntiva (2FA): se quella fallisce, il contenuto del vault non sarà
// mai esistito in chiaro in questa sessione.
// Non è un metodo della classe Vault perché non modifica né richiede lo stato di un'istanza.
export async function verifyPasswordAndGetVaultKey(password, packedData, secretKeyRaw = null) {
  try {
    return await unwrapVaultKeyWithPassword(password, packedData, secretKeyRaw);
  } catch (e) {
    if (e.message === 'SECRET_KEY_REQUIRED') throw e; // non "nascondere" questo caso dietro "password errata"
    throw new Error("Password errata o dati corrotti");
  }
}

export class Vault {
  constructor() {
    this.items = {};
    this.categories = [];
    this.vaultKeyRaw = null;
    this.envelope = null; // { salt, ivKey, encryptedVaultKey, magic } - l'involucro protetto dalla password (ed eventualmente dalla Secret Key)
    this.unlocked = false;
    this.lastUpdated = null;
  }

  async create(masterPassword) {
    this.items = {};
    this.categories = ['Personale', 'Lavoro', 'Finanza'];
    this.lastUpdated = new Date().toISOString();
    const vaultJson = JSON.stringify({ items: this.items, categories: this.categories, lastUpdated: this.lastUpdated });
    const { packed, vaultKeyRaw, envelope } = await packVault(masterPassword, vaultJson);
    this.vaultKeyRaw = vaultKeyRaw;
    this.envelope = envelope;
    this.unlocked = true;
    return packed;
  }

  async unlock(masterPassword, encryptedData, secretKeyRaw = null) {
    try {
      const { vaultJson, vaultKeyRaw, envelope } = await unpackVault(masterPassword, encryptedData, secretKeyRaw);
      const parsed = JSON.parse(vaultJson);
      this.items = parsed.items || {};
      this.categories = parsed.categories || [];
      this.lastUpdated = parsed.lastUpdated || new Date().toISOString();
      this.vaultKeyRaw = vaultKeyRaw;
      this.envelope = envelope;
      this.unlocked = true;
      return true;
    } catch (e) {
      if (e.message === 'SECRET_KEY_REQUIRED') throw e;
      throw new Error("Password errata o dati corrotti");
    }
  }

  // Sblocca avendo già la vaultKey grezza (32 byte), ottenuta tramite un secondo fattore
  // (biometria WebAuthn/PRF o TOTP) invece che dalla password principale. Vedi twofactor.js.
  async unlockWithVaultKey(vaultKeyRaw, encryptedData) {
    try {
      const { vaultJson, envelope } = await unpackVaultWithKey(vaultKeyRaw, encryptedData);
      const parsed = JSON.parse(vaultJson);
      this.items = parsed.items || {};
      this.categories = parsed.categories || [];
      this.lastUpdated = parsed.lastUpdated || new Date().toISOString();
      this.vaultKeyRaw = vaultKeyRaw;
      this.envelope = envelope;
      this.unlocked = true;
      return true;
    } catch (e) {
      throw new Error("Impossibile sbloccare il vault con la chiave fornita");
    }
  }

  lock() {
    if (this.vaultKeyRaw) {
      wipeBuffer(this.vaultKeyRaw);
      this.vaultKeyRaw = null;
    }
    this.envelope = null;
    this.items = {};
    this.categories = [];
    this.unlocked = false;
  }

  isUnlocked() {
    return this.unlocked;
  }

  // Vero se il vault attualmente sbloccato usa la protezione 2SKD (password + Secret Key).
  isTwoSecretKeyDerivationEnabled() {
    return !!(this.envelope && this.envelope.magic);
  }

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

  // Ri-cifra e restituisce il vault pronto per essere salvato. Non richiede più la password:
  // riusa la vaultKey e l'involucro (envelope) già noti da quando il vault è stato sbloccato
  // (con password oppure con biometria/TOTP), quindi funziona indipendentemente dal metodo
  // di sblocco usato.
  async getEncryptedData() {
    if (!this.unlocked || !this.vaultKeyRaw || !this.envelope) throw new Error("Vault is locked");
    const vaultJson = JSON.stringify({ items: this.items, categories: this.categories, lastUpdated: this.lastUpdated });
    return await repackVaultData(this.vaultKeyRaw, vaultJson, this.envelope);
  }

  // Cambia la password principale. Riusa la vaultKey esistente (non ne genera una nuova):
  // questo evita di dover ri-cifrare tutti i dati e, soprattutto, mantiene valide le eventuali
  // registrazioni biometriche/TOTP già effettuate (che proteggono una copia della vaultKey).
  // Se il vault usa la protezione 2SKD, va fornita anche la Secret Key corrente (la Secret Key
  // stessa NON cambia con la password, esattamente come in 1Password).
  async changeMasterPassword(currentPassword, newPassword, secretKeyRaw = null) {
    if (!this.unlocked || !this.vaultKeyRaw) throw new Error("Vault is locked");
    const vaultJson = JSON.stringify({ items: this.items, categories: this.categories, lastUpdated: this.lastUpdated });

    let result;
    if (this.isTwoSecretKeyDerivationEnabled()) {
      if (!secretKeyRaw) throw new Error("SECRET_KEY_REQUIRED");
      result = await packVault2SKD(newPassword, secretKeyRaw, vaultJson, this.vaultKeyRaw);
    } else {
      result = await packVault(newPassword, vaultJson, this.vaultKeyRaw);
    }

    this.vaultKeyRaw = result.vaultKeyRaw;
    this.envelope = result.envelope;
    return result.packed;
  }

  // Attiva la protezione 2SKD (Two-Secret Key Derivation) su un vault che finora ne era privo:
  // genera una nuova Secret Key ad alta entropia e ri-avvolge la vaultKey ESISTENTE (quindi
  // biometria/TOTP già configurati restano validi) usando password + Secret Key combinate.
  // Richiede la password corrente per riconferma, come per il cambio password.
  // Restituisce sia il blob da salvare, sia la Secret Key formattata da mostrare UNA VOLTA
  // SOLA all'utente: non viene mai salvata dall'app stessa fuori da questo dispositivo.
  async enableTwoSecretKeyDerivation(currentPassword) {
    if (!this.unlocked || !this.vaultKeyRaw) throw new Error("Vault is locked");
    const vaultJson = JSON.stringify({ items: this.items, categories: this.categories, lastUpdated: this.lastUpdated });

    const secretKeyRaw = generateSecretKeyRaw();
    const { packed, vaultKeyRaw, envelope } = await packVault2SKD(currentPassword, secretKeyRaw, vaultJson, this.vaultKeyRaw);

    this.vaultKeyRaw = vaultKeyRaw;
    this.envelope = envelope;

    return { packed, secretKeyFormatted: formatSecretKey(secretKeyRaw) };
  }

  getStats() {
    return {
      totalItems: Object.keys(this.items).length,
      categories: this.categories.length,
      lastUpdated: this.lastUpdated
    };
  }
}
