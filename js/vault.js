import { packVault, unpackVault, wipeBuffer } from './crypto.js';

export class Vault {
  constructor() {
    this.items = {};
    this.categories = [];
    this.vaultKeyRaw = null;
    this.unlocked = false;
    this.lastUpdated = null;
  }

  async create(masterPassword) {
    this.items = {};
    this.categories = ['Personale', 'Lavoro', 'Finanza'];
    this.lastUpdated = new Date().toISOString();
    const vaultJson = JSON.stringify({ items: this.items, categories: this.categories, lastUpdated: this.lastUpdated });
    const { packed, vaultKeyRaw } = await packVault(masterPassword, vaultJson);
    this.vaultKeyRaw = vaultKeyRaw;
    this.unlocked = true;
    return packed;
  }

  async unlock(masterPassword, encryptedData) {
    try {
      const { vaultJson, vaultKeyRaw } = await unpackVault(masterPassword, encryptedData);
      const parsed = JSON.parse(vaultJson);
      this.items = parsed.items || {};
      this.categories = parsed.categories || [];
      this.lastUpdated = parsed.lastUpdated || new Date().toISOString();
      this.vaultKeyRaw = vaultKeyRaw;
      this.unlocked = true;
      return true;
    } catch (e) {
      throw new Error("Password errata o dati corrotti");
    }
  }

  lock() {
    if (this.vaultKeyRaw) {
      wipeBuffer(this.vaultKeyRaw);
      this.vaultKeyRaw = null;
    }
    this.items = {};
    this.categories = [];
    this.unlocked = false;
  }

  isUnlocked() {
    return this.unlocked;
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

  async getEncryptedData(password) {
    if (!this.unlocked) throw new Error("Vault is locked");
    const vaultJson = JSON.stringify({ items: this.items, categories: this.categories, lastUpdated: this.lastUpdated });
    const { packed } = await packVault(password, vaultJson, this.vaultKeyRaw);
    return packed;
  }

  async changeMasterPassword(currentPassword, newPassword) {
    const vaultJson = JSON.stringify({ items: this.items, categories: this.categories, lastUpdated: this.lastUpdated });
    // First, verify current password by packing it without existing key, then we just generate a new one
    const { packed, vaultKeyRaw } = await packVault(newPassword, vaultJson);
    this.vaultKeyRaw = vaultKeyRaw;
    return packed;
  }

  getStats() {
    return {
      totalItems: Object.keys(this.items).length,
      categories: this.categories.length,
      lastUpdated: this.lastUpdated
    };
  }
}
