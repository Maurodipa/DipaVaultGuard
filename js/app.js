import { Vault } from './vault.js';
import { GoogleDriveClient } from './drive.js';
import * as UI from './ui.js';

let appVault = new Vault();
let driveClient = null;
let currentVaultFileId = null;
let appPassword = null; // Stored in memory to allow save/sync

const LOCAL_STORAGE_KEY = 'dipavaultguard_vault';
const SETTINGS_KEY = 'dipavaultguard_settings';
const CLIENT_ID_KEY = 'dipavaultguard_client_id';
// Determina quale Client ID usare:
// Se l'utente ne ha salvato uno personalizzato nelle impostazioni usa quello, altrimenti usa il default
const DEFAULT_GOOGLE_CLIENT_ID = '751284166814-p2u156n0btpstlg1anlnlhl8nlia0pi7.apps.googleusercontent.com';

let settings = {
  autoLockMinutes: 5,
  googleClientId: ''
};

// Attende che la libreria Google Identity Services sia effettivamente disponibile
// (lo script è caricato con async/defer e potrebbe non essere pronto subito).
function waitForGoogleIdentity(timeoutMs = 8000, intervalMs = 150) {
  return new Promise((resolve) => {
    const start = Date.now();
    const check = () => {
      if (typeof google !== 'undefined' && google.accounts && google.accounts.oauth2) {
        resolve(true);
        return;
      }
      if (Date.now() - start >= timeoutMs) {
        resolve(false);
        return;
      }
      setTimeout(check, intervalMs);
    };
    check();
  });
}

document.addEventListener('DOMContentLoaded', async () => {
  // Load settings
  const storedSettings = localStorage.getItem(SETTINGS_KEY);
  if (storedSettings) {
    try {
      settings = { ...settings, ...JSON.parse(storedSettings) };
    } catch (e) {}
  }

  // Initialize Drive Client (usa quello salvato o il default di codice)
  const activeClientId = (settings.googleClientId && settings.googleClientId.trim() !== '') 
    ? settings.googleClientId 
    : DEFAULT_GOOGLE_CLIENT_ID;

  if (activeClientId) {
    driveClient = new GoogleDriveClient(activeClientId);
    // Attende che lo script di Google sia caricato prima di inizializzare,
    // così quando l'utente clicca "Connetti" il client è già pronto e la
    // richiesta di accesso parte subito, in risposta diretta al click.
    waitForGoogleIdentity().then((ready) => {
      if (ready) {
        driveClient.init();
      } else {
        console.warn("Google Identity Services non disponibile dopo l'attesa iniziale.");
      }
    });
  }

  UI.initUI(appVault, driveClient);
  
  // Apply settings to UI
  const autoLockSelect = document.getElementById('settings-autolock');
  if (autoLockSelect) autoLockSelect.value = settings.autoLockMinutes;
  const clientIdInput = document.getElementById('settings-google-client-id');
  if (clientIdInput) clientIdInput.value = settings.googleClientId;

  // Wait a moment for UI to settle
  setTimeout(checkInitialState, 500);

  setupEventListeners();
});

async function checkInitialState() {
  const localVaultData = localStorage.getItem(LOCAL_STORAGE_KEY);
  
  if (localVaultData) {
    document.getElementById('login-vault-info').textContent = "Vault locale trovato";
    UI.showScreen('screen-login');
  } else {
    // No local vault
    UI.showScreen('screen-setup');
  }
}

async function saveAndSync() {
  if (!appVault.isUnlocked() || !appPassword) return;

  try {
    const encryptedBlob = await appVault.getEncryptedData(appPassword);
    
    // 1. Save to local storage (Base64 encoding since localStorage needs strings)
    const base64Data = arrayBufferToBase64(encryptedBlob);
    localStorage.setItem(LOCAL_STORAGE_KEY, base64Data);

    // 2. Sync to Drive if connected
    if (driveClient && driveClient.isAuthenticated()) {
      UI.updateSyncStatus('syncing');
      try {
        if (!currentVaultFileId) {
          const file = await driveClient.findVaultFile();
          if (file) {
            currentVaultFileId = file.id;
          }
        }
        
        if (currentVaultFileId) {
          await driveClient.updateVaultFile(currentVaultFileId, encryptedBlob);
        } else {
          const file = await driveClient.createVaultFile(encryptedBlob);
          currentVaultFileId = file.id;
        }
        UI.updateSyncStatus('synced');
      } catch (e) {
        console.error("Drive sync error:", e);
        UI.updateSyncStatus('error');
      }
    }
  } catch (err) {
    console.error("Error saving vault:", err);
    UI.showToast("Errore durante il salvataggio", "error");
  }
}

function setupEventListeners() {
  // Vault Updated
  document.addEventListener('vault-updated', () => {
    saveAndSync();
    UI.renderItemList(appVault.getAllItems());
    UI.renderCategories(appVault.getCategories(), null);
  });

  // Auto Lock
  document.addEventListener('auto-lock', () => {
    if (appVault.isUnlocked()) {
      appVault.lock();
      appPassword = null;
      UI.showToast("Vault bloccato automaticamente per inattività", "info");
      UI.showScreen('screen-login');
      document.getElementById('login-password').value = '';
    }
  });

  // FORM: Setup
  const formSetup = document.getElementById('form-setup');
  if (formSetup) {
    formSetup.addEventListener('submit', async (e) => {
      e.preventDefault();
      const pwd = document.getElementById('setup-password').value;
      const pwdConfirm = document.getElementById('setup-confirm-password').value;
      
      if (pwd !== pwdConfirm) {
        UI.showToast("Le password non coincidono", "error");
        return;
      }
      if (pwd.length < 8) {
        UI.showToast("La password deve essere di almeno 8 caratteri", "error");
        return;
      }

      UI.showScreen('screen-loading');
      try {
        appPassword = pwd;
        const packed = await appVault.create(appPassword);
        
        // Save to local storage
        localStorage.setItem(LOCAL_STORAGE_KEY, arrayBufferToBase64(packed));
        
        UI.showToast("Vault creato con successo!", "success");
        
        UI.showScreen('screen-dashboard');
        UI.renderItemList(appVault.getAllItems());
        UI.renderCategories(appVault.getCategories(), null);
        UI.resetAutoLockTimer();
      } catch (err) {
        console.error(err);
        UI.showToast("Errore durante la creazione", "error");
        UI.showScreen('screen-setup');
      }
    });
  }

  // FORM: Login
  const formLogin = document.getElementById('form-login');
  if (formLogin) {
    formLogin.addEventListener('submit', async (e) => {
      e.preventDefault();
      const pwd = document.getElementById('login-password').value;
      const localVaultData = localStorage.getItem(LOCAL_STORAGE_KEY);
      
      if (!localVaultData) {
        UI.showToast("Nessun vault locale trovato", "error");
        return;
      }

      const errorDiv = document.getElementById('login-error');
      errorDiv.classList.add('hidden');
      UI.showScreen('screen-loading');

      try {
        const encryptedBlob = base64ToArrayBuffer(localVaultData);
        await appVault.unlock(pwd, encryptedBlob);
        appPassword = pwd;
        
        document.getElementById('login-password').value = '';
        UI.showToast("Vault sbloccato", "success");
        UI.showScreen('screen-dashboard');
        UI.renderItemList(appVault.getAllItems());
        UI.renderCategories(appVault.getCategories(), null);
        UI.resetAutoLockTimer();
        
        // Try to sync if connected
        if (driveClient && driveClient.isAuthenticated()) {
          syncFromDrive();
        }
      } catch (err) {
        console.error(err);
        errorDiv.textContent = "Password principale errata";
        errorDiv.classList.remove('hidden');
        UI.showScreen('screen-login');
      }
    });
  }

  // FORM: Item Edit/Add
  const formItemEdit = document.getElementById('form-item-edit');
  if (formItemEdit) {
    formItemEdit.addEventListener('submit', (e) => {
      e.preventDefault();
      
      const id = document.getElementById('edit-item-id').value;
      const itemData = {
        name: document.getElementById('edit-item-name').value,
        url: document.getElementById('edit-item-url').value,
        username: document.getElementById('edit-item-username').value,
        password: document.getElementById('edit-item-password').value,
        notes: document.getElementById('edit-item-notes').value,
        category: document.getElementById('edit-item-category').value,
        favorite: document.getElementById('edit-item-favorite').checked,
        type: 'login'
      };
      
      if (id) {
        appVault.updateItem(id, itemData);
      } else {
        appVault.addItem(itemData);
      }
      
      document.getElementById('modal-item-edit').classList.add('hidden');
      UI.showToast("Voce salvata", "success");
      document.dispatchEvent(new CustomEvent('vault-updated'));
    });
  }

  /*
  // Delete Item
  const btnDelete = document.getElementById('btn-view-delete');
  if (btnDelete) {
    btnDelete.addEventListener('click', () => {
      if (confirm("Sei sicuro di voler eliminare questa voce?")) {
        const id = document.getElementById('view-item-name').getAttribute('data-id'); // assuming ui.js sets this
        if (id) {
          appVault.deleteItem(id);
          document.getElementById('modal-item-view').classList.add('hidden');
          UI.showToast("Voce eliminata", "info");
          document.dispatchEvent(new CustomEvent('vault-updated'));
        }
      }
    });
  }
  */

  // Change password form
  const formChangePwd = document.getElementById('form-change-password');
  if (formChangePwd) {
    formChangePwd.addEventListener('submit', async (e) => {
      e.preventDefault();
      const current = document.getElementById('change-pwd-current').value;
      const newPwd = document.getElementById('change-pwd-new').value;
      const confirmPwd = document.getElementById('change-pwd-confirm').value;
      
      if (current !== appPassword) {
        UI.showToast("La password attuale non è corretta", "error");
        return;
      }
      if (newPwd !== confirmPwd) {
        UI.showToast("Le nuove password non coincidono", "error");
        return;
      }
      if (newPwd.length < 8) {
        UI.showToast("La password deve essere di almeno 8 caratteri", "error");
        return;
      }

      try {
        UI.showToast("Cambio password in corso...", "info");
        await appVault.changeMasterPassword(current, newPwd);
        appPassword = newPwd;
        
        formChangePwd.reset();
        document.dispatchEvent(new CustomEvent('vault-updated'));
        UI.showToast("Password principale cambiata con successo!", "success");
      } catch (err) {
        console.error(err);
        UI.showToast("Errore durante il cambio password", "error");
      }
    });
  }

  // Drive Connect from Login
  const btnLoginDrive = document.getElementById('btn-login-drive');
  if (btnLoginDrive) {
    btnLoginDrive.addEventListener('click', async () => {
      if (!driveClient) {
        UI.showToast("Configura il Google Client ID nelle impostazioni prima", "warning");
        return;
      }
      try {
        await driveClient.authenticate();
        UI.showToast("Google Drive connesso", "success");
        await syncFromDrive(true);
      } catch (err) {
        console.error(err);
        UI.showToast("Errore di connessione a Drive", "error");
      }
    });
  }
  
  // Drive Connect/Disconnect from Settings
  const btnSettingsDriveToggle = document.getElementById('btn-settings-drive-toggle');
  if (btnSettingsDriveToggle) {
    btnSettingsDriveToggle.addEventListener('click', async () => {
      if (!driveClient) return;
      if (driveClient.isAuthenticated()) {
        driveClient.signOut();
        UI.showToast("Disconnesso da Drive", "info");
        btnSettingsDriveToggle.textContent = 'Connetti';
      } else {
        try {
          await driveClient.authenticate();
          UI.showToast("Connesso a Drive", "success");
          btnSettingsDriveToggle.textContent = 'Disconnetti';
          syncFromDrive();
        } catch (e) {
          console.error(e);
          UI.showToast("Errore di connessione", "error");
        }
      }
    });
  }

  // Sync Now button
  const btnSyncNow = document.getElementById('btn-settings-sync-now');
  if (btnSyncNow) {
    btnSyncNow.addEventListener('click', () => {
      saveAndSync();
    });
  }

  // Lock button
  const btnLock = document.getElementById('btn-lock');
  if (btnLock) {
    btnLock.addEventListener('click', () => {
      if (appVault.isUnlocked()) {
        appVault.lock();
        appPassword = null;
        UI.showToast("Vault bloccato", "info");
        UI.showScreen('screen-login');
        document.getElementById('login-password').value = '';
      }
    });
  }

  // Settings sync
  const settingsFormFields = ['settings-autolock', 'settings-google-client-id'];
  settingsFormFields.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('change', () => {
        if (id === 'settings-autolock') {
          settings.autoLockMinutes = parseInt(el.value, 10);
          UI.resetAutoLockTimer();
        } else if (id === 'settings-google-client-id') {
          settings.googleClientId = el.value.trim();
          const currentId = settings.googleClientId || DEFAULT_GOOGLE_CLIENT_ID;
          if (currentId) {
            driveClient = new GoogleDriveClient(currentId);
            waitForGoogleIdentity().then((ready) => {
              if (ready) driveClient && driveClient.init();
            });
          } else {
            driveClient = null;
          }
        }
        localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
      });
    }
  });

  // Reset vault (Impostazioni) - richiede tripla conferma per evitare click accidentali
  const btnSettingsReset = document.getElementById('btn-settings-reset-vault');
  if (btnSettingsReset) {
    btnSettingsReset.addEventListener('click', () => {
      // Step 1: conferma iniziale
      const step1 = confirm("Attenzione: questa operazione eliminerà il vault locale in modo irreversibile. Vuoi procedere?");
      if (!step1) return;

      // Step 2: digitare DELETE
      const token = prompt("Per confermare, digita DELETE (tutto maiuscolo):");
      if (!token || token !== 'DELETE') {
        UI.showToast("Conferma non valida. Operazione annullata.", "warning");
        return;
      }

      // Step 3: conferma finale
      const step3 = confirm("Ultima conferma: sei sicuro di voler eliminare definitivamente il vault locale?");
      if (!step3) {
        UI.showToast("Operazione annullata.", "info");
        return;
      }

      // Esegue il reset
      localStorage.removeItem(LOCAL_STORAGE_KEY);
      appVault = new Vault();
      appPassword = null;
      UI.initUI(appVault, driveClient); // re-init
      UI.showToast("Vault locale eliminato", "success");
      UI.showScreen('screen-setup');
    });
  }

  // Add Category
  const btnAddCategory = document.getElementById('btn-add-category');
  if (btnAddCategory) {
    btnAddCategory.addEventListener('click', () => {
      const catName = prompt("Nome della nuova categoria:");
      if (catName && catName.trim()) {
        appVault.addCategory(catName.trim());
        document.dispatchEvent(new CustomEvent('vault-updated'));
      }
    });
  }
  // Drive Connect / Restore from Setup Screen
// Drive Connect / Restore from Setup Screen
  const btnSetupDrive = document.getElementById('btn-setup-drive');
  if (btnSetupDrive) {
    btnSetupDrive.addEventListener('click', async () => {
      // Usa il client ID salvato o il default inserito nel codice
      const activeClientId = (settings.googleClientId && settings.googleClientId.trim() !== '') 
        ? settings.googleClientId 
        : DEFAULT_GOOGLE_CLIENT_ID;

      if (!activeClientId) {
        UI.showToast("Google Client ID non configurato", "error");
        return;
      }

      // Se il client non è inizializzato, lo crea al volo con l'ID attivo
      if (!driveClient) {
        driveClient = new GoogleDriveClient(activeClientId);
        try {
          driveClient.init();
        } catch (e) {}
      }

      try {
        UI.showToast("Connessione a Google Drive in corso...", "info");
        await driveClient.authenticate();
        UI.showToast("Connesso a Google Drive", "success");
        
        // Cerca il file del vault su Drive
        const file = await driveClient.findVaultFile();
        if (file) {
          currentVaultFileId = file.id;
          const remoteData = await driveClient.readVaultFile(file.id);
          
          const pwd = prompt("Inserisci la password principale del vault salvato su Google Drive:");
          if (pwd) {
            UI.showScreen('screen-loading');
            try {
              await appVault.unlock(pwd, remoteData);
              appPassword = pwd;
              localStorage.setItem(LOCAL_STORAGE_KEY, arrayBufferToBase64(remoteData));
              
              UI.showToast("Vault scaricato e sbloccato con successo!", "success");
              UI.showScreen('screen-dashboard');
              UI.renderItemList(appVault.getAllItems());
              UI.renderCategories(appVault.getCategories(), null);
              UI.resetAutoLockTimer();
            } catch (err) {
              console.error(err);
              UI.showToast("Password errata o file non valido", "error");
              UI.showScreen('screen-setup');
            }
          }
        } else {
          UI.showToast("Nessun vault trovato su Google Drive", "warning");
        }
      } catch (err) {
        console.error("Drive setup error:", err);
        UI.showToast("Errore di connessione a Google Drive", "error");
      }
    });
  }
}

async function syncFromDrive(forceUnlockPrompt = false) {
  if (!driveClient || !driveClient.isAuthenticated()) return;
  UI.updateSyncStatus('syncing');
  try {
    const file = await driveClient.findVaultFile();
    if (file) {
      currentVaultFileId = file.id;
      const remoteData = await driveClient.readVaultFile(file.id);
      
      if (forceUnlockPrompt && !appVault.isUnlocked()) {
        // Just downloaded, need password to unlock
        const pwd = prompt("Inserisci la password principale per il vault di Drive:");
        if (pwd) {
          try {
            await appVault.unlock(pwd, remoteData);
            appPassword = pwd;
            localStorage.setItem(LOCAL_STORAGE_KEY, arrayBufferToBase64(remoteData));
            
            UI.showToast("Vault sincronizzato da Drive e sbloccato", "success");
            UI.showScreen('screen-dashboard');
            UI.renderItemList(appVault.getAllItems());
            UI.renderCategories(appVault.getCategories(), null);
            UI.resetAutoLockTimer();
          } catch(e) {
            UI.showToast("Password errata", "error");
          }
        }
      } else if (appVault.isUnlocked()) {
        // We are already unlocked. We should try to unlock remote data with same password to merge or overwrite.
        // For simplicity in this version, we will overwrite local if remote is newer, or overwrite remote if local is newer.
        // Usually, proper sync requires merging items. Here we just take the newest vault file.
        // A better implementation would unpack remote and compare timestamps.
        
        try {
          // Verify we can open it
          const tempVault = new Vault();
          await tempVault.unlock(appPassword, remoteData);
          
          const localStats = appVault.getStats();
          const remoteStats = tempVault.getStats();
          
          const localTime = new Date(localStats.lastUpdated).getTime();
          const remoteTime = new Date(remoteStats.lastUpdated).getTime();
          
          if (remoteTime > localTime) {
            // Replace local
            appVault = tempVault;
            UI.initUI(appVault, driveClient);
            localStorage.setItem(LOCAL_STORAGE_KEY, arrayBufferToBase64(remoteData));
            UI.renderItemList(appVault.getAllItems());
            UI.renderCategories(appVault.getCategories(), null);
            UI.showToast("Vault aggiornato da Drive", "info");
          } else if (localTime > remoteTime) {
            // Push local to remote
            saveAndSync();
          }
        } catch (e) {
          console.warn("Could not unlock remote vault with current password. Passwords might differ.");
        }
      }
    }
    UI.updateSyncStatus('synced');
  } catch (err) {
    console.error("Sync error:", err);
    UI.updateSyncStatus('error');
  }
}


// --- Helper Functions for Base64 <-> ArrayBuffer ---
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}