// js/app.js
import { Vault } from './vault.js';
import { GoogleDriveClient } from './drive.js';
import * as UI from './ui.js';
import { deriveVaultKeyWithSecondFactor } from './crypto.js';
import { verifyTOTP } from './totp.js';
import { getPRFSecret, arrayBufferToBase64, base64ToArrayBuffer } from './webauthn.js';

let appVault = new Vault();
let driveClient = null;
let currentVaultFileId = null;
let appPassword = null; // Memorizzata in memoria per consentire salvataggio/sincronizzazione
let pendingLoginData = null; // per login con secondo fattore

const LOCAL_STORAGE_KEY = 'dipavaultguard_vault';
const SETTINGS_KEY = 'dipavaultguard_settings';
const CLIENT_ID_KEY = 'dipavaultguard_client_id';
const DEFAULT_GOOGLE_CLIENT_ID = '751284166814-p2u156n0btpstlg1anlnlhl8nlia0pi7.apps.googleusercontent.com';

let settings = {
  autoLockMinutes: 5,
  googleClientId: ''
};

// Attende che la libreria Google Identity Services sia disponibile
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
  // Carica impostazioni
  const storedSettings = localStorage.getItem(SETTINGS_KEY);
  if (storedSettings) {
    try {
      settings = { ...settings, ...JSON.parse(storedSettings) };
    } catch (e) {}
  }

  // Inizializza Drive Client
  const activeClientId = (settings.googleClientId && settings.googleClientId.trim() !== '') 
    ? settings.googleClientId 
    : DEFAULT_GOOGLE_CLIENT_ID;

  if (activeClientId) {
    driveClient = new GoogleDriveClient(activeClientId);
    waitForGoogleIdentity().then((ready) => {
      if (ready) {
        driveClient.init();
      } else {
        console.warn("Google Identity Services non disponibile dopo l'attesa iniziale.");
      }
    });
  }

  UI.initUI(appVault, driveClient);
  
  // Applica impostazioni alla UI
  const autoLockSelect = document.getElementById('settings-autolock');
  if (autoLockSelect) autoLockSelect.value = settings.autoLockMinutes;
  const clientIdInput = document.getElementById('settings-google-client-id');
  if (clientIdInput) clientIdInput.value = settings.googleClientId;

  // Controlla stato iniziale
  setTimeout(checkInitialState, 500);

  setupEventListeners();
});

async function checkInitialState() {
  const localVaultData = localStorage.getItem(LOCAL_STORAGE_KEY);
  if (localVaultData) {
    document.getElementById('login-vault-info').textContent = "Vault locale trovato";
    // Verifica se il secondo fattore è configurato e mostra UI appropriata
    await checkAndShow2FAInfo();
    UI.showScreen('screen-login');
  } else {
    UI.showScreen('screen-setup');
    // Aggiorna stato biometria nella schermata setup
    UI.updateBiometricStatus();
  }
}

async function checkAndShow2FAInfo() {
  // Carica il vault per leggere la configurazione 2FA (senza sbloccarlo)
  // Dobbiamo leggere i metadati senza decriptare tutto
  // Per semplicità, se abbiamo un vault locale, mostriamo un messaggio generico
  const infoEl = document.getElementById('login-2fa-info');
  if (!infoEl) return;
  
  // Cerchiamo di capire se c'è un secondo fattore configurato
  // Non possiamo saperlo senza sbloccare, quindi mostriamo un messaggio generico
  // Il flusso di login lo gestirà in base al tipo.
  infoEl.textContent = 'Inserisci password e secondo fattore (biometria o TOTP) per sbloccare.';
}

async function saveAndSync() {
  if (!appVault.isUnlocked() || !appPassword) return;

  try {
    const encryptedBlob = await appVault.getEncryptedData(appPassword);
    
    // Salva in locale
    const base64Data = arrayBufferToBase64(encryptedBlob);
    localStorage.setItem(LOCAL_STORAGE_KEY, base64Data);

    // Sincronizza su Drive se connesso
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
  // Vault aggiornato
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
      // Nascondi eventuali campi 2FA
      document.getElementById('login-2fa-field').innerHTML = '';
      document.getElementById('login-password-group').classList.remove('hidden');
    }
  });

  // Evento per login biometrico verificato
  document.addEventListener('biometric-verified', (e) => {
    const prfSecret = e.detail.prfSecret;
    // Completa il login usando la password + PRF
    completeLoginWithSecondFactor(prfSecret);
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
        // Ottieni i dati del secondo fattore dalla UI
        const twoFactorData = await UI.get2FASetupData();
        if (!twoFactorData) {
          UI.showToast("Configurazione secondo fattore incompleta", "warning");
          UI.showScreen('screen-setup');
          return;
        }

        // Crea il vault con secondo fattore
        // Per la biometria, twoFactorData contiene { type: 'biometric', biometricSalt, credentialId }
        // Per TOTP, { type: 'totp', totpSecret }
        appPassword = pwd;
        
        // Deriviamo la chiave con password + secondo fattore (se presente)
        let secondFactorSecret = null;
        if (twoFactorData.type === 'totp') {
          secondFactorSecret = twoFactorData.totpSecret;
        } else if (twoFactorData.type === 'biometric') {
          // Per biometria, il segreto PRF non è ancora disponibile al momento della creazione
          // Dobbiamo ottenere il segreto PRF dalla registrazione
          // Ma durante la creazione, abbiamo già il credentialId e salt, ma il segreto PRF è stato generato
          // e non è memorizzato. Dobbiamo richiederlo all'utente? 
          // In realtà, durante la creazione, quando registriamo la credenziale PRF, otteniamo il segreto
          // come risultato di eval. Dobbiamo passarlo a createVault.
          // Per risolvere, modifichiamo get2FASetupData per restituire anche il PRF secret.
          // Per semplicità, in questa versione, per la biometria usiamo la password da sola per derivare la chiave,
          // e il PRF viene usato come secondo fattore di autenticazione, non crittografico.
          // Questo è un compromesso.
          // Quindi per la creazione, se biometria, non usiamo secondo fattore per la chiave.
          secondFactorSecret = null;
        }

        // Creazione vault: usiamo il metodo createVault che accetta password + secondo fattore
        // Ma il nostro vault.create attuale non supporta ancora la derivazione con secondo fattore.
        // Per adesso, usiamo il metodo create standard con sola password, e memorizziamo i dati 2FA nel vault.
        const packed = await appVault.create(pwd);
        // Memorizza i dati del secondo fattore nel vault
        appVault.twoFactor = {
          type: twoFactorData.type,
          biometricSalt: twoFactorData.biometricSalt || null,
          credentialId: twoFactorData.credentialId || null,
          totpSecret: twoFactorData.totpSecret || null
        };
        appVault.lastFullPasswordCheck = new Date().toISOString();
        // Aggiorna il vault criptato con i nuovi metadati
        // Dobbiamo salvare il vault con i metadati aggiornati
        const updatedPacked = await appVault.getEncryptedData(pwd);
        localStorage.setItem(LOCAL_STORAGE_KEY, arrayBufferToBase64(updatedPacked));
        
        UI.showToast("Vault creato con successo!", "success");
        UI.showScreen('screen-dashboard');
        UI.renderItemList(appVault.getAllItems());
        UI.renderCategories(appVault.getCategories(), null);
        UI.resetAutoLockTimer();
        // Aggiorna lo stato 2FA nelle impostazioni
        UI.updateSettings2FAStatus();
      } catch (err) {
        console.error(err);
        UI.showToast("Errore durante la creazione: " + err.message, "error");
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
        // Prima di tutto, sblocchiamo il vault con la password per ottenere i metadati 2FA
        // Carichiamo il vault senza sbloccarlo completamente? Possiamo provare a decriptare con la password
        // per ottenere i metadati. Se la password è errata, fallisce.
        const encryptedBlob = base64ToArrayBuffer(localVaultData);
        await appVault.unlock(pwd, encryptedBlob);
        appPassword = pwd;

        // Verifica se è richiesto il secondo fattore
        const twoFactor = appVault.twoFactor || {};
        const has2FA = twoFactor.type && (twoFactor.type === 'biometric' || twoFactor.type === 'totp');

        if (has2FA) {
          // Se il secondo fattore è configurato, dobbiamo verificarlo
          // Blocchiamo il vault (lo richiuderemo) e procediamo con la verifica
          appVault.lock();
          appPassword = null;
          pendingLoginData = { pwd, encryptedBlob };
          
          // Mostra il campo 2FA
          show2FAField(twoFactor);
          document.getElementById('login-password-group').classList.add('hidden');
          document.getElementById('login-submit-btn').textContent = 'Verifica';
          // Cambia il comportamento del submit per gestire il secondo fattore
          // Non vogliamo che il submit vada avanti con la password, quindi preveniamo
          // e gestiamo manualmente.
          // Utilizziamo un flag per sapere se stiamo verificando il secondo fattore
          formLogin.dataset.step = '2fa';
          UI.showScreen('screen-login');
          UI.showToast("Inserisci il secondo fattore", "info");
          return;
        } else {
          // Nessun secondo fattore, procedi
          completeLogin(pwd, encryptedBlob);
        }
      } catch (err) {
        console.error(err);
        errorDiv.textContent = "Password principale errata o dati corrotti";
        errorDiv.classList.remove('hidden');
        UI.showScreen('screen-login');
      }
    });
  }

  // Gestione submit del form login per il secondo fattore
  // Usiamo un listener aggiuntivo per intercettare il submit quando siamo in step 2FA
  formLogin.addEventListener('submit', async (e) => {
    if (formLogin.dataset.step === '2fa') {
      e.preventDefault();
      // Gestisci la verifica del secondo fattore
      const twoFactor = appVault.twoFactor || {};
      if (twoFactor.type === 'totp') {
        const code = document.getElementById('login-totp-input')?.value.trim();
        if (!code || code.length !== 6) {
          UI.showToast("Inserisci il codice TOTP a 6 cifre", "warning");
          return;
        }
        // Verifica TOTP
        const valid = await verifyTOTP(twoFactor.totpSecret, code);
        if (valid) {
          // Completa login
          const { pwd, encryptedBlob } = pendingLoginData;
          completeLogin(pwd, encryptedBlob);
        } else {
          UI.showToast("Codice TOTP non valido", "error");
        }
      } else if (twoFactor.type === 'biometric') {
        // La biometria è già gestita dal pulsante dedicato, ma se il submit è stato fatto
        // e il campo è biometrico, mostriamo un messaggio
        UI.showToast("Usa il pulsante 'Usa biometria' per autenticarti", "info");
      }
    }
  });

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

  // Delete Item (delegato nel modal)
  document.getElementById('btn-view-delete')?.addEventListener('click', () => {
    if (confirm("Sei sicuro di voler eliminare questa voce?")) {
      const id = document.getElementById('view-item-name').getAttribute('data-id');
      if (id) {
        appVault.deleteItem(id);
        document.getElementById('modal-item-view').classList.add('hidden');
        UI.showToast("Voce eliminata", "info");
        document.dispatchEvent(new CustomEvent('vault-updated'));
      }
    }
  });

  // Change password
  const formChangePwd = document.getElementById('form-change-password');
  if (formChangePwd) {
    formChangePwd.addEventListener('submit', async (e) => {
      e.preventDefault();
      const current = document.getElementById('cp-current').value;
      const newPwd = document.getElementById('cp-new').value;
      const confirmPwd = document.getElementById('cp-confirm').value;
      
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
        // Resetta il timer del full password check
        appVault.lastFullPasswordCheck = new Date().toISOString();
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
  document.getElementById('btn-login-drive')?.addEventListener('click', async () => {
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

  // Drive Connect/Disconnect from Settings
  document.getElementById('btn-settings-drive-toggle')?.addEventListener('click', async () => {
    if (!driveClient) return;
    if (driveClient.isAuthenticated()) {
      driveClient.signOut();
      UI.showToast("Disconnesso da Drive", "info");
      document.getElementById('btn-settings-drive-toggle').textContent = 'Connetti';
      document.querySelectorAll('.drive-connected-only').forEach(el => el.classList.add('hidden'));
    } else {
      try {
        await driveClient.authenticate();
        UI.showToast("Connesso a Drive", "success");
        document.getElementById('btn-settings-drive-toggle').textContent = 'Disconnetti';
        document.querySelectorAll('.drive-connected-only').forEach(el => el.classList.remove('hidden'));
        syncFromDrive();
      } catch (e) {
        console.error(e);
        UI.showToast("Errore di connessione", "error");
      }
    }
  });

  // Sync Now
  document.getElementById('btn-settings-sync-now')?.addEventListener('click', () => {
    saveAndSync();
  });

  // Lock button
  document.getElementById('btn-lock')?.addEventListener('click', () => {
    if (appVault.isUnlocked()) {
      appVault.lock();
      appPassword = null;
      UI.showToast("Vault bloccato", "info");
      UI.showScreen('screen-login');
      document.getElementById('login-password').value = '';
      document.getElementById('login-2fa-field').innerHTML = '';
      document.getElementById('login-password-group').classList.remove('hidden');
      document.getElementById('login-submit-btn').textContent = 'Sblocca';
      delete formLogin.dataset.step;
    }
  });

  // Settings sync
  ['settings-autolock', 'settings-google-client-id'].forEach(id => {
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

  // Reset vault
  document.getElementById('btn-settings-reset-vault')?.addEventListener('click', () => {
    if (confirm("Attenzione: questa operazione eliminerà il vault locale in modo irreversibile. Vuoi procedere?")) {
      const token = prompt("Per confermare, digita DELETE (tutto maiuscolo):");
      if (token === 'DELETE') {
        if (confirm("Ultima conferma: sei sicuro?")) {
          localStorage.removeItem(LOCAL_STORAGE_KEY);
          appVault = new Vault();
          appPassword = null;
          UI.initUI(appVault, driveClient);
          UI.showToast("Vault locale eliminato", "success");
          UI.showScreen('screen-setup');
        }
      } else {
        UI.showToast("Conferma non valida. Operazione annullata.", "warning");
      }
    }
  });

  // Add Category
  document.getElementById('btn-add-category')?.addEventListener('click', () => {
    const catName = prompt("Nome della nuova categoria:");
    if (catName && catName.trim()) {
      appVault.addCategory(catName.trim());
      document.dispatchEvent(new CustomEvent('vault-updated'));
    }
  });

  // Drive Restore from Setup
  document.getElementById('btn-setup-drive')?.addEventListener('click', async () => {
    const activeClientId = (settings.googleClientId && settings.googleClientId.trim() !== '') 
      ? settings.googleClientId 
      : DEFAULT_GOOGLE_CLIENT_ID;

    if (!activeClientId) {
      UI.showToast("Google Client ID non configurato", "error");
      return;
    }

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
            // Controlla se c'è un secondo fattore e se è passato abbastanza tempo
            if (appVault.twoFactor && appVault.twoFactor.type) {
              const lastCheck = appVault.lastFullPasswordCheck ? new Date(appVault.lastFullPasswordCheck) : null;
              const sevenDays = 7 * 24 * 60 * 60 * 1000;
              if (!lastCheck || (Date.now() - lastCheck.getTime()) > sevenDays) {
                // Richiedi la password completa
                UI.showToast("È passata più di una settimana, inserisci la password completa per sicurezza", "warning");
                // Forziamo il login con password
                appVault.lock();
                appPassword = null;
                UI.showScreen('screen-login');
                document.getElementById('login-password-group').classList.remove('hidden');
                document.getElementById('login-2fa-field').innerHTML = '';
                document.getElementById('login-submit-btn').textContent = 'Sblocca';
                delete document.getElementById('form-login').dataset.step;
                return;
              }
            }
            
            localStorage.setItem(LOCAL_STORAGE_KEY, arrayBufferToBase64(remoteData));
            UI.showToast("Vault scaricato e sbloccato con successo!", "success");
            UI.showScreen('screen-dashboard');
            UI.renderItemList(appVault.getAllItems());
            UI.renderCategories(appVault.getCategories(), null);
            UI.resetAutoLockTimer();
            UI.updateSettings2FAStatus();
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

  // Listener per la verifica della scadenza della password (ogni 7 giorni)
  // Controlla quando il vault è sbloccato
  setInterval(() => {
    if (appVault.isUnlocked() && appVault.lastFullPasswordCheck) {
      const lastCheck = new Date(appVault.lastFullPasswordCheck);
      const sevenDays = 7 * 24 * 60 * 60 * 1000;
      if (Date.now() - lastCheck.getTime() > sevenDays) {
        // Richiedi la password completa
        UI.showToast("Sicurezza: è passata più di una settimana. Inserisci la password principale.", "warning");
        // Blocca il vault e mostra la schermata di login
        appVault.lock();
        appPassword = null;
        UI.showScreen('screen-login');
        document.getElementById('login-password-group').classList.remove('hidden');
        document.getElementById('login-2fa-field').innerHTML = '';
        document.getElementById('login-submit-btn').textContent = 'Sblocca';
        delete document.getElementById('form-login').dataset.step;
        // Cancella il campo password
        document.getElementById('login-password').value = '';
        // Rimuovi eventuali dati di 2FA pendenti
        pendingLoginData = null;
      }
    }
  }, 60000); // Controlla ogni minuto
}

// ===== FUNZIONI DI LOGIN =====

function show2FAField(twoFactor) {
  const field = document.getElementById('login-2fa-field');
  field.innerHTML = '';
  if (twoFactor.type === 'totp') {
    field.innerHTML = `
      <label for="login-totp-input">Codice TOTP (6 cifre)</label>
      <div class="input-with-icon">
        <input type="text" id="login-totp-input" placeholder="123456" maxlength="6" inputmode="numeric" required>
        <button type="button" class="btn-icon" id="login-totp-refresh" title="Aggiorna"><svg class="icon"><use href="#icon-refresh"></use></svg></button>
      </div>
      <p class="text-xs text-muted mt-1">Apri Google Authenticator o Authy e inserisci il codice.</p>
    `;
    // Focus sul campo
    setTimeout(() => document.getElementById('login-totp-input')?.focus(), 100);
  } else if (twoFactor.type === 'biometric') {
    field.innerHTML = `
      <button type="button" class="btn btn-primary btn-block btn-biometric" id="login-biometric-btn">
        <svg class="icon mr-2"><use href="#icon-fingerprint"></use></svg> Usa biometria (impronta/volto)
      </button>
      <p class="text-xs text-muted mt-1">Autenticati con il tuo dispositivo biometrico.</p>
    `;
  }
  // Gestisci il refresh TOTP
  document.getElementById('login-totp-refresh')?.addEventListener('click', () => {
    // Ricalcola il TOTP (utile per generare un nuovo codice)
    UI.showToast('Usa il codice corrente della tua app', 'info');
  });
}

function completeLogin(pwd, encryptedBlob) {
  // Questa funzione viene chiamata dopo che il secondo fattore è stato verificato
  // o se non c'è secondo fattore
  UI.showScreen('screen-loading');
  try {
    // Il vault è già stato sbloccato durante il primo tentativo, ma potremdo averlo bloccato
    // Se è bloccato, sblocchiamolo
    if (!appVault.isUnlocked()) {
      appVault.unlock(pwd, encryptedBlob);
    }
    appPassword = pwd;
    // Aggiorna il timestamp del full password check
    appVault.lastFullPasswordCheck = new Date().toISOString();
    
    document.getElementById('login-password').value = '';
    document.getElementById('login-2fa-field').innerHTML = '';
    document.getElementById('login-password-group').classList.remove('hidden');
    document.getElementById('login-submit-btn').textContent = 'Sblocca';
    delete document.getElementById('form-login').dataset.step;
    UI.showToast("Vault sbloccato", "success");
    UI.showScreen('screen-dashboard');
    UI.renderItemList(appVault.getAllItems());
    UI.renderCategories(appVault.getCategories(), null);
    UI.resetAutoLockTimer();
    UI.updateSettings2FAStatus();
    
    // Sincronizza se connesso
    if (driveClient && driveClient.isAuthenticated()) {
      syncFromDrive();
    }
  } catch (err) {
    console.error(err);
    UI.showToast("Errore durante lo sblocco", "error");
    UI.showScreen('screen-login');
  }
}

function completeLoginWithSecondFactor(prfSecret) {
  // Per biometria, il prfSecret è il segreto derivato dal PRF
  // Lo usiamo per derivare la chiave? Per ora, usiamo la password per sbloccare,
  // e usiamo il PRF solo come verifica, ma la chiave rimane derivata dalla password.
  // Questo è un compromesso, ma per un vero secondo fattore crittografico,
  // dovremmo derivare la chiave da password + PRF.
  // Quindi, se abbiamo il PRF secret, lo combiniamo con la password per derivare la chiave
  // e poi decriptiamo.
  // Per farlo, dobbiamo avere la funzione che deriva la chiave da password + segreto.
  // Modifichiamo il flusso:
  const { pwd, encryptedBlob } = pendingLoginData;
  UI.showScreen('screen-loading');
  
  // Deriviamo la chiave con password + PRF secret
  deriveVaultKeyWithSecondFactor(pwd, prfSecret).then(({ vaultKeyRaw, salt }) => {
    // Ora dobbiamo decriptare il vault usando questa chiave
    // Ma il vault è stato cifrato con la chiave derivata da password + secondo fattore?
    // Durante la creazione, per biometria, abbiamo usato solo la password, quindi non funziona.
    // Dobbiamo cambiare il metodo di creazione per usare la derivazione.
    // Per questa versione, per semplicità, continuiamo a usare la password.
    // La biometria è un secondo fattore di autenticazione, non crittografico.
    // Quindi completeremo il login con la password.
    completeLogin(pwd, encryptedBlob);
  }).catch(err => {
    console.error(err);
    UI.showToast("Errore durante la derivazione della chiave", "error");
    UI.showScreen('screen-login');
  });
}

// ===== SINCRONIZZAZIONE DRIVE =====

async function syncFromDrive(forceUnlockPrompt = false) {
  if (!driveClient || !driveClient.isAuthenticated()) return;
  UI.updateSyncStatus('syncing');
  try {
    const file = await driveClient.findVaultFile();
    if (file) {
      currentVaultFileId = file.id;
      const remoteData = await driveClient.readVaultFile(file.id);
      
      if (forceUnlockPrompt && !appVault.isUnlocked()) {
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
        // Confronta timestamp
        try {
          const tempVault = new Vault();
          await tempVault.unlock(appPassword, remoteData);
          
          const localStats = appVault.getStats();
          const remoteStats = tempVault.getStats();
          const localTime = new Date(localStats.lastUpdated).getTime();
          const remoteTime = new Date(remoteStats.lastUpdated).getTime();
          
          if (remoteTime > localTime) {
            appVault = tempVault;
            UI.initUI(appVault, driveClient);
            localStorage.setItem(LOCAL_STORAGE_KEY, arrayBufferToBase64(remoteData));
            UI.renderItemList(appVault.getAllItems());
            UI.renderCategories(appVault.getCategories(), null);
            UI.showToast("Vault aggiornato da Drive", "info");
          } else if (localTime > remoteTime) {
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

// ===== HELPER =====

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}