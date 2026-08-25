// (inizio file invariato: import, variabili, DOMContentLoaded, ecc.)
// ... (mantieni tutto quanto già presente fino a setupEventListeners)

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

  // NOTE: Reset vault removed from welcome/setup screen to avoid accidental deletion.
  // The original code used:
  // if (confirm("Attenzione: questo eliminerà il vault locale in modo irreversibile! Vuoi procedere?")) { ... }
  // That behavior is now available only in Settings with triple confirmation.

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
            driveClient.init();
          } else {
            driveClient = null;
          }
        }
        localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
      });
    }
  });

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

  // Reset vault moved to Settings with triple confirmation
  const btnSettingsReset = document.getElementById('btn-settings-reset-vault');
  if (btnSettingsReset) {
    btnSettingsReset.addEventListener('click', () => {
      // Step 1: initial confirm
      const step1 = confirm("Attenzione: questa operazione eliminerà il vault locale in modo irreversibile. Vuoi procedere?");
      if (!step1) return;

      // Step 2: type DELETE
      const token = prompt("Per confermare, digita DELETE (tutto maiuscolo):");
      if (!token || token !== 'DELETE') {
        UI.showToast("Conferma non valida. Operazione annullata.", "warning");
        return;
      }

      // Step 3: final confirm
      const step3 = confirm("Ultima conferma: sei sicuro di voler eliminare definitivamente il vault locale?");
      if (!step3) {
        UI.showToast("Operazione annullata.", "info");
        return;
      }

      // Perform reset
      localStorage.removeItem(LOCAL_STORAGE_KEY);
      appVault = new Vault();
      appPassword = null;
      UI.initUI(appVault, driveClient); // re-init 
      UI.showToast("Vault locale eliminato", "success");
      UI.showScreen('screen-setup');
    });
  }

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

// (resto del file invariato: syncFromDrive, helper functions, ecc.)
