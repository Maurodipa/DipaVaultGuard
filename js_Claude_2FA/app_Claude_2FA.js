import { Vault, verifyPasswordAndGetVaultKey, isSecretKeyRequired, parseSecretKey } from './vault_Claude_2FA.js';
import { GoogleDriveClient } from './drive_Claude_2FA.js';
import * as UI from './ui_Claude_2FA.js';
import * as TwoFactor from './twofactor_Claude_2FA.js';
import * as EmailOTP from './email-otp_Claude_2FA.js';

let appVault = new Vault();
let driveClient = null;
let currentVaultFileId = null;
let appPassword = null; // Stored in memory to allow save/sync
let pendingTotpSecret = null; // Segreto TOTP generato ma non ancora confermato dall'utente
let otpVerificationMode = 'email'; // 'email' | 'totp' — modalità attiva sulla schermata screen-otp-verify
// Durante l'attesa della verifica aggiuntiva (email/TOTP) dopo il percorso password, il vault
// NON viene ancora decifrato: si tiene solo la vaultKey (32 byte) e il blob cifrato originale,
// e si decifra il contenuto vero e proprio solo dopo che la verifica extra è stata superata.
let pendingVaultKeyRaw = null;
let pendingEncryptedBlob = null;
let pendingPersistLocally = false; // se true, al termine della verifica il blob va salvato anche in localStorage (ripristino da Drive)

const LOCAL_STORAGE_KEY = 'dipavaultguard_vault';
const SETTINGS_KEY = 'dipavaultguard_settings';
// Secret Key del 2SKD: SOLO locale, MAI sincronizzata su Drive (è l'intero senso della
// protezione). Salvata qui dopo il primo inserimento su un dispositivo, così non va
// re-inserita a ogni sblocco — esattamente come fa 1Password.
const SECRET_KEY_STORAGE_KEY = 'dipavaultguard_secret_key';
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
    refreshLoginQuickUnlockUI();
  } else {
    // No local vault
    UI.showScreen('screen-setup');
  }
}

// Genera un nuovo segreto TOTP e apre il modal che mostra la chiave (e l'URI otpauth://) da
// aggiungere a un'app authenticator, in attesa che l'utente confermi con un codice valido.
function openTotpSetup() {
  pendingTotpSecret = TwoFactor.generateTOTPSecret();
  document.getElementById('totp-secret-display').textContent = TwoFactor.formatSecretForDisplay(pendingTotpSecret);
  document.getElementById('totp-uri-display').textContent = TwoFactor.getTOTPUri(pendingTotpSecret);
  document.getElementById('totp-confirm-code').value = '';
  document.getElementById('modal-totp-setup').classList.remove('hidden');
}

// Mostra il pulsante di sblocco biometrico e/o il campo per il codice 2FA nella schermata
// di login, solo se registrati su questo dispositivo E se non sono ancora passati più di
// 7 giorni dall'ultima volta che è stata usata la password completa.
//
// IMPORTANTE: quando un metodo rapido è attivo, il form della password viene nascosto di
// default (non solo "in secondo piano"), e si mostra al suo posto un link esplicito da
// cliccare deliberatamente. Questo impedisce che l'autoriempimento della password salvata
// dal telefono renda il secondo fattore inutile (bastava aprire l'app e toccare "Sblocca").
// Il form password resta comunque raggiungibile come via di emergenza, per non rischiare di
// bloccare fuori il proprietario del vault se la biometria smette di funzionare.
function refreshLoginQuickUnlockUI() {
  const container = document.getElementById('login-quick-unlock');
  const btnBiometric = document.getElementById('btn-login-biometric');
  const formTotp = document.getElementById('form-login-totp');
  const formLogin = document.getElementById('form-login');
  const fallbackLinkWrap = document.getElementById('login-password-fallback-link');
  if (!container || !btnBiometric || !formTotp || !formLogin || !fallbackLinkWrap) return;

  const canQuickUnlock = TwoFactor.canUseQuickUnlock();
  const showBiometric = canQuickUnlock && TwoFactor.isBiometricRegistered();
  const showTotp = canQuickUnlock && TwoFactor.isTOTPRegistered();
  const quickUnlockActive = showBiometric || showTotp;

  container.classList.toggle('hidden', !quickUnlockActive);
  btnBiometric.classList.toggle('hidden', !showBiometric);
  formTotp.classList.toggle('hidden', !showTotp);

  if (quickUnlockActive) {
    formLogin.classList.add('hidden');
    fallbackLinkWrap.classList.remove('hidden');
  } else {
    // Nessun metodo rapido attivo (o sono passati più di 7 giorni): la password torna
    // a essere l'unica via, quindi va mostrata normalmente.
    formLogin.classList.remove('hidden');
    fallbackLinkWrap.classList.add('hidden');
  }
}

// Rivela manualmente il form della password (via di emergenza), nascondendo il link che lo
// mostra. Usata sia dal click esplicito dell'utente sia automaticamente se un tentativo di
// sblocco biometrico/TOTP fallisce, per non lasciare la persona bloccata senza opzioni visibili.
function revealPasswordLoginForm() {
  const formLogin = document.getElementById('form-login');
  const fallbackLinkWrap = document.getElementById('login-password-fallback-link');
  if (formLogin) formLogin.classList.remove('hidden');
  if (fallbackLinkWrap) fallbackLinkWrap.classList.add('hidden');
}

// Vero se questo vault richiede una verifica aggiuntiva oltre alla password: se biometria o
// TOTP sono registrati su questo dispositivo, OPPURE se è configurato l'OTP via email (locale
// o appena adottato da Drive). Quest'ultimo caso è importante: rende il requisito "serve altro
// oltre alla password" una proprietà del vault, non solo di questo dispositivo — così anche
// ripristinando il vault su un browser/dispositivo dove non è mai stata configurata la
// biometria, se la configurazione OTP viene trovata su Drive, la password da sola non basta.
function requiresExtraVerification() {
  return TwoFactor.isBiometricRegistered() || TwoFactor.isTOTPRegistered() || EmailOTP.isEmailOtpConfigured();
}

// Recupera la Secret Key necessaria per sbloccare un blob 2SKD: se è già stata salvata su
// Legge la Secret Key salvata su questo dispositivo, se presente. Riconosce sia il vecchio
// formato in chiaro (stringa semplice) sia quello nuovo cifrato con la biometria (oggetto
// JSON {encrypted:true, iv, wrapped}), per restare compatibile con quanto già salvato in
// precedenza. Se è cifrata, chiede la verifica biometrica per decifrarla.
async function readCachedSecretKeyString() {
  const raw = localStorage.getItem(SECRET_KEY_STORAGE_KEY);
  if (!raw) return null;

  let parsed = null;
  try { parsed = JSON.parse(raw); } catch (e) { /* non è JSON: formato legacy in chiaro */ }

  if (parsed && parsed.encrypted) {
    if (!TwoFactor.isBiometricRegistered()) {
      throw new Error("La Secret Key salvata è protetta dalla biometria, ma la biometria non risulta configurata su questo dispositivo.");
    }
    UI.showToast("Conferma l'impronta/volto per recuperare la Secret Key salvata...", "info");
    try {
      return await TwoFactor.decryptSecretKeyWithBiometric(parsed);
    } catch (e) {
      // Il messaggio dell'eccezione originale (spesso una DOMException generica di
      // crypto.subtle) può essere vuoto o poco chiaro: senza questo passaggio esplicito,
      // il chiamante rischia di scambiare questo fallimento per una password sbagliata.
      console.error("Impossibile decifrare la Secret Key salvata con la biometria:", e);
      throw new Error("Impossibile recuperare la Secret Key salvata tramite biometria. Riprova, oppure inseriscila manualmente.");
    }
  }

  return raw; // formato legacy: stringa in chiaro
}

// Salva la Secret Key su questo dispositivo. Se la biometria è già configurata qui, la cifra
// prima di salvarla (così un accesso diretto a localStorage non basta a leggerla); altrimenti
// la salva in chiaro come prima, dato che non c'è un modo sicuro alternativo di proteggerla
// localmente senza un fattore biometrico.
async function cacheSecretKeyLocally(secretKeyFormatted) {
  if (TwoFactor.isBiometricRegistered()) {
    try {
      const record = await TwoFactor.encryptSecretKeyWithBiometric(secretKeyFormatted);
      localStorage.setItem(SECRET_KEY_STORAGE_KEY, JSON.stringify({ encrypted: true, ...record }));
      return;
    } catch (e) {
      console.warn("Impossibile cifrare la Secret Key con la biometria, la salvo in chiaro:", e);
    }
  }
  localStorage.setItem(SECRET_KEY_STORAGE_KEY, secretKeyFormatted);
}

// Se sul dispositivo è già salvata una Secret Key in chiaro (formato legacy, da prima che la
// biometria fosse configurata), e la biometria è appena diventata disponibile, la ricifra
// automaticamente. Non fa nulla se non c'è alcuna Secret Key salvata, o se è già cifrata.
async function upgradePlaintextSecretKeyToEncrypted() {
  const raw = localStorage.getItem(SECRET_KEY_STORAGE_KEY);
  if (!raw) return;
  try {
    JSON.parse(raw);
    return; // è già in formato JSON cifrato, niente da fare
  } catch (e) {
    // non è JSON: è la stringa in chiaro legacy, procediamo a cifrarla
  }
  try {
    await cacheSecretKeyLocally(raw);
  } catch (e) {
    console.warn("Impossibile mettere in sicurezza la Secret Key già salvata:", e);
  }
}

// Recupera (o richiede all'utente, una tantum per dispositivo) la Secret Key necessaria per
// sbloccare un blob 2SKD. Restituisce null se il blob non richiede affatto la Secret Key
// (formato v1, il caso comune).
async function getSecretKeyRawForBlob(blob) {
  if (!isSecretKeyRequired(blob)) return null;

  const cached = await readCachedSecretKeyString();
  if (cached) return parseSecretKey(cached);

  const entered = prompt("Questo vault richiede anche la Secret Key (oltre alla password) — l'hai salvata quando hai attivato la protezione 2SKD:");
  if (!entered || !entered.trim()) {
    throw new Error("Secret Key necessaria per sbloccare questo vault.");
  }
  const trimmed = entered.trim();
  await cacheSecretKeyLocally(trimmed);
  return parseSecretKey(trimmed);
}

// Verifica la password su un blob cifrato qualsiasi (locale o appena scaricato da Drive) e,
// se serve, avvia la verifica aggiuntiva SENZA decifrare ancora il contenuto del vault.
// Se `persistLocally` è vero, il blob verrà salvato anche in localStorage una volta completata
// (o immediatamente, se non serve alcuna verifica extra) — usato per il ripristino da Drive.
async function unlockBlobWithPasswordAndVerification(pwd, blob, persistLocally = false) {
  const secretKeyRaw = await getSecretKeyRawForBlob(blob); // null se il blob non è 2SKD

  if (requiresExtraVerification()) {
    const vaultKeyRaw = await verifyPasswordAndGetVaultKey(pwd, blob, secretKeyRaw);
    pendingVaultKeyRaw = vaultKeyRaw;
    pendingEncryptedBlob = blob;
    pendingPersistLocally = persistLocally;
    await startPostPasswordVerification();
    return;
  }

  await appVault.unlock(pwd, blob, secretKeyRaw);
  appPassword = pwd;
  if (persistLocally) {
    localStorage.setItem(LOCAL_STORAGE_KEY, arrayBufferToBase64(blob));
  }
  TwoFactor.markFullPasswordAuth();
  UI.showToast("Vault sbloccato", "success");
  UI.showScreen('screen-dashboard');
  UI.renderItemList(appVault.getAllItems());
  UI.renderCategories(appVault.getCategories(), null);
  UI.resetAutoLockTimer();
  if (driveClient && driveClient.isAuthenticated()) {
    syncFromDrive();
  }
}

// Scarica (se presente) la configurazione OTP via email salvata su Drive e la adotta
// localmente, così questo dispositivo la userà da subito, anche se non era mai stata
// configurata qui prima.
async function adoptRemoteOtpConfigIfPresent() {
  if (!driveClient || !driveClient.isAuthenticated()) return;
  try {
    const file = await driveClient.findOtpConfigFile();
    if (file) {
      const remoteConfig = await driveClient.readOtpConfigFile(file.id);
      if (remoteConfig && remoteConfig.serviceId && remoteConfig.templateId && remoteConfig.publicKey && remoteConfig.recipientEmail) {
        EmailOTP.saveConfig(remoteConfig);
      }
    }
  } catch (e) {
    console.warn("Impossibile recuperare la configurazione OTP da Drive:", e);
  }
}

// Avvia la verifica aggiuntiva obbligatoria dopo che la password è risultata corretta, quando
// biometria e/o TOTP e/o email sono già configurati su questo dispositivo: la sola password
// non deve mai bastare in quel caso. Prova prima l'email (se configurata); se l'invio fallisce
// (es. offline) o l'email non è configurata, propone TOTP e/o la biometria come alternativa
// (a seconda di cosa è disponibile). IMPORTANTE: la biometria è un metodo di verifica valido
// tanto quanto email/TOTP — prima di questa correzione veniva ignorata qui, così chi aveva
// configurato SOLO la biometria (senza TOTP né email) restava bloccato fuori ogni volta che
// il percorso "password" veniva usato (es. per collegare Google Drive), perché il codice
// dichiarava necessaria una verifica aggiuntiva ma non ne offriva mai una soddisfacibile.
// Se non c'è alcun metodo utilizzabile, annulla e ributta alla schermata di login.
async function startPostPasswordVerification() {
  const totpFallbackAvailable = TwoFactor.isTOTPRegistered();
  const biometricFallbackAvailable = TwoFactor.isBiometricRegistered() && await TwoFactor.isPlatformAuthenticatorAvailable();
  document.getElementById('otp-verify-error').classList.add('hidden');
  document.getElementById('otp-verify-code').value = '';
  document.getElementById('btn-otp-resend').classList.add('hidden');

  UI.showScreen('screen-otp-verify');
  UI.resetAutoLockTimer(); // la vaultKey temporanea è comunque sensibile: non lasciarla in sospeso a tempo indeterminato

  if (EmailOTP.isEmailOtpConfigured()) {
    await trySendEmailOtp(totpFallbackAvailable, biometricFallbackAvailable);
  } else if (totpFallbackAvailable) {
    switchOtpScreenToTotpMode(biometricFallbackAvailable);
  } else if (biometricFallbackAvailable) {
    switchOtpScreenToBiometricMode();
  } else {
    UI.showToast("Nessun metodo di verifica aggiuntivo configurato. Configuralo nelle impostazioni prima di riprovare.", "error");
    cancelPostPasswordVerification();
  }
}

async function trySendEmailOtp(totpFallbackAvailable, biometricFallbackAvailable = false) {
  otpVerificationMode = 'email';
  document.getElementById('otp-verify-mode').textContent = 'Ti abbiamo inviato un codice via email. Controlla la posta in arrivo.';
  document.getElementById('form-otp-verify').classList.remove('hidden');
  document.getElementById('btn-otp-verify-biometric').classList.add('hidden');
  toggleOtpAlternativeLinks(totpFallbackAvailable, biometricFallbackAvailable);
  try {
    await EmailOTP.sendOtp();
    document.getElementById('btn-otp-resend').classList.remove('hidden');
    UI.showToast("Codice inviato via email", "info");
  } catch (err) {
    console.error(err);
    if (totpFallbackAvailable) {
      UI.showToast("Invio email non riuscito (sei offline?). Usa il codice dell'app authenticator.", "warning");
      switchOtpScreenToTotpMode(biometricFallbackAvailable);
    } else if (biometricFallbackAvailable) {
      UI.showToast("Invio email non riuscito (sei offline?). Usa l'impronta/volto.", "warning");
      switchOtpScreenToBiometricMode();
    } else {
      UI.showToast("Invio email non riuscito e nessun metodo alternativo configurato.", "error");
      cancelPostPasswordVerification();
    }
  }
}

function switchOtpScreenToTotpMode(biometricFallbackAvailable = false) {
  otpVerificationMode = 'totp';
  document.getElementById('otp-verify-mode').textContent = 'Inserisci il codice a 6 cifre dalla tua app authenticator.';
  document.getElementById('form-otp-verify').classList.remove('hidden');
  document.getElementById('btn-otp-verify-biometric').classList.add('hidden');
  document.getElementById('btn-otp-resend').classList.add('hidden');
  toggleOtpAlternativeLinks(false, biometricFallbackAvailable);
  document.getElementById('otp-verify-code').value = '';
  document.getElementById('otp-verify-code').focus();
}

// Nuova modalità: conferma tramite biometria (WebAuthn/PRF), usata quando è l'unico metodo
// disponibile (o scelta esplicitamente dall'utente come alternativa a email/TOTP). Non c'è
// nessun codice da digitare: un tap avvia subito la richiesta di impronta/volto, esattamente
// come lo sblocco rapido nella schermata di login, ma qui serve solo a CONFERMARE il secondo
// fattore (la vaultKey ottenuta per questa via sostituisce quella temporanea derivata dalla
// password, che viene azzerata).
function switchOtpScreenToBiometricMode() {
  otpVerificationMode = 'biometric';
  document.getElementById('otp-verify-mode').textContent = 'Conferma con impronta o volto per completare l\'accesso.';
  document.getElementById('form-otp-verify').classList.add('hidden');
  document.getElementById('btn-otp-verify-biometric').classList.remove('hidden');
  document.getElementById('btn-otp-resend').classList.add('hidden');
  toggleOtpAlternativeLinks(TwoFactor.isTOTPRegistered(), false);
}

// Mostra/nasconde i link "usa invece..." per passare a un metodo diverso da quello corrente.
function toggleOtpAlternativeLinks(showTotpLink, showBiometricLink) {
  document.getElementById('otp-use-totp-instead').classList.toggle('hidden', !showTotpLink);
  document.getElementById('otp-use-biometric-instead').classList.toggle('hidden', !showBiometricLink);
}

// Esegue la conferma biometrica e completa lo sblocco. La vaultKey ottenuta per via biometrica
// è calcolata in modo del tutto indipendente da quella derivata dalla password: usarla al posto
// di quella "in sospeso" è la prova crittografica reale del secondo fattore, non solo un
// controllo a schermo.
async function handleBiometricPostPasswordVerification() {
  const errorDiv = document.getElementById('otp-verify-error');
  errorDiv.classList.add('hidden');
  try {
    // La biometria qui serve SOLO come prova di possesso del dispositivo (secondo fattore):
    // la vaultKey che conta davvero resta quella già verificata pochi istanti fa tramite
    // password (+ eventuale Secret Key), che è garantita corretta per QUESTO blob specifico.
    // NON va sostituita con quella ottenuta per via biometrica: sono normalmente identiche,
    // ma la registrazione biometrica è locale a questo dispositivo e, in teoria, potrebbe
    // riferirsi a una versione diversa del vault (es. se il file su Drive fosse più recente
    // di quando la biometria fu registrata l'ultima volta) — usarla al posto della chiave
    // già verificata rischierebbe di introdurre esattamente quel tipo di disallineamento.
    const biometricVaultKeyRaw = await TwoFactor.unlockWithBiometric();
    crypto.getRandomValues(biometricVaultKeyRaw); // era solo per la verifica, va scartata subito
    await completePostPasswordVerification();
  } catch (err) {
    console.error(err);
    errorDiv.textContent = err.message || "Verifica biometrica non riuscita.";
    errorDiv.classList.remove('hidden');
  }
}

// Verifica completata con successo: SOLO ORA si decifra davvero il contenuto del vault
// (finora si aveva solo la vaultKey temporanea, non i dati), e si procede alla dashboard
// esattamente come un login normale.
async function completePostPasswordVerification() {
  await appVault.unlockWithVaultKey(pendingVaultKeyRaw, pendingEncryptedBlob);
  if (pendingPersistLocally) {
    localStorage.setItem(LOCAL_STORAGE_KEY, arrayBufferToBase64(pendingEncryptedBlob));
  }
  pendingVaultKeyRaw = null;
  pendingEncryptedBlob = null;
  pendingPersistLocally = false;

  TwoFactor.markFullPasswordAuth();
  document.getElementById('otp-verify-code').value = '';
  UI.showToast("Verifica completata, vault sbloccato", "success");
  UI.showScreen('screen-dashboard');
  UI.renderItemList(appVault.getAllItems());
  UI.renderCategories(appVault.getCategories(), null);
  UI.resetAutoLockTimer();
  if (driveClient && driveClient.isAuthenticated()) {
    syncFromDrive();
  }
}

// Annulla la verifica aggiuntiva. Il contenuto del vault non è MAI stato decifrato in questo
// percorso (solo la vaultKey grezza era temporaneamente in memoria): basta sovrascrivere quei
// 32 byte e scartarli, senza dover "ribloccare" dati che non sono mai esistiti in chiaro.
function cancelPostPasswordVerification() {
  EmailOTP.clearPendingOtp();
  if (pendingVaultKeyRaw) {
    crypto.getRandomValues(pendingVaultKeyRaw);
    pendingVaultKeyRaw = null;
  }
  pendingEncryptedBlob = null;
  const wasPersisting = pendingPersistLocally; // true se veniva da un ripristino Drive (nessun vault locale ancora)
  pendingPersistLocally = false;
  appPassword = null;
  UI.showScreen(wasPersisting ? 'screen-setup' : 'screen-login');
  refreshLoginQuickUnlockUI();
}

async function saveAndSync() {
  if (!appVault.isUnlocked()) return;

  try {
    // Non serve più la password in memoria: la vaultKey e l'involucro (envelope) sono già
    // noti al vault dallo sblocco (con password, oppure con biometria/TOTP).
    const encryptedBlob = await appVault.getEncryptedData();
    
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
    const wasUnlocked = appVault.isUnlocked();
    const hadPendingVerification = !!pendingVaultKeyRaw;
    const wasPersisting = pendingPersistLocally;

    if (wasUnlocked) {
      appVault.lock();
    }
    if (hadPendingVerification) {
      // In attesa della verifica extra (email/TOTP): il contenuto del vault non è mai stato
      // decifrato, basta scartare la vaultKey temporanea rimasta in sospeso.
      crypto.getRandomValues(pendingVaultKeyRaw);
      pendingVaultKeyRaw = null;
      pendingEncryptedBlob = null;
      pendingPersistLocally = false;
      EmailOTP.clearPendingOtp();
    }

    if (wasUnlocked || hadPendingVerification) {
      appPassword = null;
      UI.showToast("Vault bloccato automaticamente per inattività", "info");
      UI.showScreen(wasPersisting ? 'screen-setup' : 'screen-login');
      document.getElementById('login-password').value = '';
      refreshLoginQuickUnlockUI();
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
        TwoFactor.markFullPasswordAuth();
        
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
        document.getElementById('login-password').value = '';
        // Verifica la password ed eventualmente avvia la verifica aggiuntiva (biometria/TOTP
        // registrati qui, o OTP via email configurato) SENZA decifrare subito il vault.
        await unlockBlobWithPasswordAndVerification(pwd, encryptedBlob, false);
      } catch (err) {
        console.error(err);
        if (err.message === 'SECRET_KEY_REQUIRED') {
          errorDiv.textContent = "Questo vault richiede anche la Secret Key. Riprova e inseriscila quando richiesta.";
        } else if (err.message && (err.message.includes('biometric') || err.message.includes('biometrica') || err.message.includes('Verifica biometrica'))) {
          errorDiv.textContent = "Verifica biometrica per la Secret Key non riuscita. Riprova, oppure controlla che l'impronta/volto sia riconosciuto correttamente.";
        } else if (err.message === 'Password errata o dati corrotti') {
          errorDiv.textContent = "Password principale errata";
        } else {
          errorDiv.textContent = err.message || "Password principale errata";
        }
        errorDiv.classList.remove('hidden');
        UI.showScreen('screen-login');
      }
    });
  }

  // Schermata di verifica aggiuntiva dopo la password (OTP email o TOTP di ripiego)
  const formOtpVerify = document.getElementById('form-otp-verify');
  if (formOtpVerify) {
    formOtpVerify.addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = document.getElementById('otp-verify-code').value;
      const errorDiv = document.getElementById('otp-verify-error');
      errorDiv.classList.add('hidden');
      try {
        if (otpVerificationMode === 'totp') {
          await TwoFactor.verifyRegisteredTOTPCode(code);
        } else {
          EmailOTP.verifyOtp(code);
        }
        await completePostPasswordVerification();
      } catch (err) {
        console.error(err);
        errorDiv.textContent = err.message || "Codice non valido";
        errorDiv.classList.remove('hidden');
      }
    });
  }

  const btnOtpResend = document.getElementById('btn-otp-resend');
  if (btnOtpResend) {
    btnOtpResend.addEventListener('click', async () => {
      btnOtpResend.disabled = true;
      btnOtpResend.textContent = 'Invio in corso...';
      const biometricAvailable = TwoFactor.isBiometricRegistered() && await TwoFactor.isPlatformAuthenticatorAvailable();
      await trySendEmailOtp(TwoFactor.isTOTPRegistered(), biometricAvailable);
      btnOtpResend.disabled = false;
      btnOtpResend.textContent = 'Invia di nuovo il codice';
    });
  }

  const btnOtpUseTotpInstead = document.getElementById('otp-use-totp-instead');
  if (btnOtpUseTotpInstead) {
    btnOtpUseTotpInstead.addEventListener('click', async () => {
      const biometricAvailable = TwoFactor.isBiometricRegistered() && await TwoFactor.isPlatformAuthenticatorAvailable();
      switchOtpScreenToTotpMode(biometricAvailable);
    });
  }

  const btnOtpUseBiometricInstead = document.getElementById('otp-use-biometric-instead');
  if (btnOtpUseBiometricInstead) {
    btnOtpUseBiometricInstead.addEventListener('click', () => {
      switchOtpScreenToBiometricMode();
    });
  }

  const btnOtpVerifyBiometric = document.getElementById('btn-otp-verify-biometric');
  if (btnOtpVerifyBiometric) {
    btnOtpVerifyBiometric.addEventListener('click', () => {
      handleBiometricPostPasswordVerification();
    });
  }

  const btnOtpCancel = document.getElementById('btn-otp-cancel');
  if (btnOtpCancel) {
    btnOtpCancel.addEventListener('click', () => {
      cancelPostPasswordVerification();
    });
  }

  // Impostazioni: configurazione OTP via email (EmailJS)
  const formEmailOtpSettings = document.getElementById('form-email-otp-settings');
  if (formEmailOtpSettings) {
    formEmailOtpSettings.addEventListener('submit', async (e) => {
      e.preventDefault();
      const recipientEmail = document.getElementById('email-otp-recipient').value.trim();
      const serviceId = document.getElementById('email-otp-service-id').value.trim();
      const templateId = document.getElementById('email-otp-template-id').value.trim();
      const publicKey = document.getElementById('email-otp-public-key').value.trim();

      if (!recipientEmail || !serviceId || !templateId || !publicKey) {
        UI.showToast("Compila tutti i campi", "error");
        return;
      }

      const config = { recipientEmail, serviceId, templateId, publicKey };
      EmailOTP.saveConfig(config);
      UI.showToast("Configurazione salvata", "success");
      UI.updateEmailOtpSettingsUI();

      // Sincronizza anche su Drive: così il requisito "serve l'email" vale per il vault
      // ovunque venga ripristinato, non solo su questo dispositivo.
      if (driveClient && driveClient.isAuthenticated()) {
        try {
          await driveClient.saveOtpConfigFile(config);
          UI.showToast("Configurazione sincronizzata anche su Google Drive", "success");
        } catch (err) {
          console.error(err);
          UI.showToast("Salvata localmente, ma la sincronizzazione su Drive non è riuscita", "warning");
        }
      }
    });
  }

  const btnEmailOtpTest = document.getElementById('btn-email-otp-test');
  if (btnEmailOtpTest) {
    btnEmailOtpTest.addEventListener('click', async () => {
      // Salva prima la configurazione corrente dai campi, così il test usa quella appena scritta
      const recipientEmail = document.getElementById('email-otp-recipient').value.trim();
      const serviceId = document.getElementById('email-otp-service-id').value.trim();
      const templateId = document.getElementById('email-otp-template-id').value.trim();
      const publicKey = document.getElementById('email-otp-public-key').value.trim();
      if (!recipientEmail || !serviceId || !templateId || !publicKey) {
        UI.showToast("Compila tutti i campi prima di inviare una prova", "error");
        return;
      }
      EmailOTP.saveConfig({ recipientEmail, serviceId, templateId, publicKey });

      btnEmailOtpTest.disabled = true;
      btnEmailOtpTest.textContent = 'Invio in corso...';
      try {
        await EmailOTP.sendTestEmail();
        UI.showToast("Email di prova inviata, controlla la posta in arrivo", "success");
        UI.updateEmailOtpSettingsUI();
      } catch (err) {
        console.error(err);
        UI.showToast(err.message || "Invio non riuscito", "error");
      } finally {
        btnEmailOtpTest.disabled = false;
        btnEmailOtpTest.textContent = 'Invia email di prova';
      }
    });
  }

  // Sblocco biometrico (WebAuthn + PRF) dalla schermata di login
  const btnLoginBiometric = document.getElementById('btn-login-biometric');
  if (btnLoginBiometric) {
    btnLoginBiometric.addEventListener('click', async () => {
      const localVaultData = localStorage.getItem(LOCAL_STORAGE_KEY);
      if (!localVaultData) {
        UI.showToast("Nessun vault locale trovato", "error");
        return;
      }
      try {
        const vaultKeyRaw = await TwoFactor.unlockWithBiometric();
        const encryptedBlob = base64ToArrayBuffer(localVaultData);
        await appVault.unlockWithVaultKey(vaultKeyRaw, encryptedBlob);
        // appPassword resta null: non l'abbiamo mai avuta in questo percorso.
        // Il salvataggio delle modifiche funziona comunque (vedi saveAndSync/getEncryptedData).

        UI.showToast("Vault sbloccato con biometria", "success");
        UI.showScreen('screen-dashboard');
        UI.renderItemList(appVault.getAllItems());
        UI.renderCategories(appVault.getCategories(), null);
        UI.resetAutoLockTimer();

        if (driveClient && driveClient.isAuthenticated()) {
          syncFromDrive();
        }
      } catch (err) {
        console.error(err);
        UI.showToast(err.message || "Sblocco biometrico non riuscito. Usa la password.", "error");
        revealPasswordLoginForm();
      }
    });
  }

  // Link "usa la password" nella schermata di login: rivela il form password su richiesta
  // esplicita dell'utente (via di emergenza quando biometria/TOTP sono attivi ma non disponibili)
  const btnShowPasswordLogin = document.getElementById('btn-show-password-login');
  if (btnShowPasswordLogin) {
    btnShowPasswordLogin.addEventListener('click', () => {
      revealPasswordLoginForm();
    });
  }

  // Sblocco con codice 2FA (TOTP) dalla schermata di login
  const formLoginTotp = document.getElementById('form-login-totp');
  if (formLoginTotp) {
    formLoginTotp.addEventListener('submit', async (e) => {
      e.preventDefault();
      const localVaultData = localStorage.getItem(LOCAL_STORAGE_KEY);
      if (!localVaultData) {
        UI.showToast("Nessun vault locale trovato", "error");
        return;
      }
      const code = document.getElementById('login-totp-code').value;
      try {
        const vaultKeyRaw = await TwoFactor.unlockWithTOTP(code);
        const encryptedBlob = base64ToArrayBuffer(localVaultData);
        await appVault.unlockWithVaultKey(vaultKeyRaw, encryptedBlob);
        document.getElementById('login-totp-code').value = '';

        UI.showToast("Vault sbloccato con codice 2FA", "success");
        UI.showScreen('screen-dashboard');
        UI.renderItemList(appVault.getAllItems());
        UI.renderCategories(appVault.getCategories(), null);
        UI.resetAutoLockTimer();

        if (driveClient && driveClient.isAuthenticated()) {
          syncFromDrive();
        }
      } catch (err) {
        console.error(err);
        UI.showToast(err.message || "Codice 2FA errato", "error");
        revealPasswordLoginForm();
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
      const current = document.getElementById('cp-current').value;
      const newPwd = document.getElementById('cp-new').value;
      const confirmPwd = document.getElementById('cp-confirm').value;

      // Verifica la password attuale in modo crittografico (prova a sbloccare una copia del
      // vault salvato localmente), invece di confrontarla con la variabile in memoria: dopo
      // uno sblocco biometrico/TOTP, appPassword è null, quindi il vecchio confronto fallirebbe
      // sempre anche inserendo la password corretta.
      const localVaultData = localStorage.getItem(LOCAL_STORAGE_KEY);
      if (!localVaultData) {
        UI.showToast("Nessun vault locale trovato", "error");
        return;
      }
      const localBlob = base64ToArrayBuffer(localVaultData);
      let secretKeyRaw = null;
      try {
        secretKeyRaw = await getSecretKeyRawForBlob(localBlob);
      } catch (e) {
        UI.showToast(e.message, "error");
        return;
      }
      try {
        const verifyVault = new Vault();
        await verifyVault.unlock(current, localBlob, secretKeyRaw);
      } catch (e) {
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
        await appVault.changeMasterPassword(current, newPwd, secretKeyRaw);
        appPassword = newPwd;
        TwoFactor.markFullPasswordAuth();
        
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
        await adoptRemoteOtpConfigIfPresent();
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

          // Se su Drive c'è già una configurazione OTP la adottiamo qui; altrimenti, se questo
          // dispositivo ne ha già una configurata localmente, la carichiamo su Drive.
          const remoteOtpFile = await driveClient.findOtpConfigFile().catch(() => null);
          if (remoteOtpFile) {
            await adoptRemoteOtpConfigIfPresent();
            UI.updateEmailOtpSettingsUI();
          } else if (EmailOTP.isEmailOtpConfigured()) {
            driveClient.saveOtpConfigFile(EmailOTP.getConfig()).catch((err) => console.warn("Impossibile caricare la configurazione OTP su Drive:", err));
          }

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
      localStorage.removeItem(SECRET_KEY_STORAGE_KEY); // legata alla vecchia vaultKey, non ha più senso
      TwoFactor.clearAllSecondFactors(); // le registrazioni 2FA proteggono la vecchia vaultKey
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

  // --- Secret Key (2SKD) ---
  let pending2SKDPacked = null; // blob generato ma non ancora persistito, in attesa di conferma
  let pending2SKDSecretKey = null;
  let pending2SKDPreviousEnvelope = null; // per poter annullare senza lasciare lo stato inconsistente

  const btnEnable2SKD = document.getElementById('btn-enable-2skd');
  const enable2SKDConfirmRow = document.getElementById('enable-2skd-confirm-row');
  const enable2SKDPasswordInput = document.getElementById('enable-2skd-password');
  const btnEnable2SKDConfirm = document.getElementById('btn-enable-2skd-confirm');
  const btnEnable2SKDCancel = document.getElementById('btn-enable-2skd-cancel');

  // NOTA: qui si usa un campo nella pagina invece di window.prompt(). Chrome (e altri
  // browser/webview mobili) può sopprimere silenziosamente i dialog nativi prompt()/alert()
  // dopo che una pagina ne ha già mostrati diversi nella stessa sessione — senza alcun
  // errore visibile: il click "funziona" ma prompt() ritorna null, e tutto sembra non fare
  // nulla. Un campo di conferma nella pagina non ha questo problema.
  if (btnEnable2SKD && enable2SKDConfirmRow) {
    btnEnable2SKD.addEventListener('click', () => {
      if (!appVault.isUnlocked()) {
        UI.showToast("Il vault deve essere sbloccato", "error");
        return;
      }
      if (appVault.isTwoSecretKeyDerivationEnabled()) {
        UI.showToast("La protezione Secret Key è già attiva su questo vault", "info");
        return;
      }
      enable2SKDPasswordInput.value = '';
      enable2SKDConfirmRow.classList.remove('hidden');
      enable2SKDPasswordInput.focus();
    });
  }

  if (btnEnable2SKDCancel && enable2SKDConfirmRow) {
    btnEnable2SKDCancel.addEventListener('click', () => {
      enable2SKDConfirmRow.classList.add('hidden');
      enable2SKDPasswordInput.value = '';
    });
  }

  if (btnEnable2SKDConfirm) {
    btnEnable2SKDConfirm.addEventListener('click', async () => {
      const current = enable2SKDPasswordInput.value;
      if (!current) return;

      // Verifica la password prima di generare qualunque cosa
      const localVaultData = localStorage.getItem(LOCAL_STORAGE_KEY);
      if (!localVaultData) {
        UI.showToast("Nessun vault locale trovato", "error");
        return;
      }
      try {
        const verifyVault = new Vault();
        await verifyVault.unlock(current, base64ToArrayBuffer(localVaultData));
      } catch (e) {
        UI.showToast("Password non corretta", "error");
        return;
      }

      try {
        pending2SKDPreviousEnvelope = appVault.envelope;
        const { packed, secretKeyFormatted } = await appVault.enableTwoSecretKeyDerivation(current);
        pending2SKDPacked = packed;
        pending2SKDSecretKey = secretKeyFormatted;

        enable2SKDConfirmRow.classList.add('hidden');
        enable2SKDPasswordInput.value = '';

        document.getElementById('secret-key-display').textContent = secretKeyFormatted;
        document.getElementById('secret-key-confirm-checkbox').checked = false;
        document.getElementById('btn-secret-key-confirm').disabled = true;
        document.getElementById('modal-2skd-reveal').classList.remove('hidden');
      } catch (err) {
        console.error(err);
        UI.showToast("Impossibile attivare la protezione", "error");
      }
    });
  }

  const secretKeyCheckbox = document.getElementById('secret-key-confirm-checkbox');
  const btnSecretKeyConfirm = document.getElementById('btn-secret-key-confirm');
  if (secretKeyCheckbox && btnSecretKeyConfirm) {
    secretKeyCheckbox.addEventListener('change', () => {
      btnSecretKeyConfirm.disabled = !secretKeyCheckbox.checked;
    });

    btnSecretKeyConfirm.addEventListener('click', async () => {
      if (!pending2SKDPacked || !pending2SKDSecretKey) return;

      // SOLO ora, dopo la conferma esplicita, si persiste davvero: prima la Secret Key non è
      // salvata da nessuna parte fuori da questa finestra, per evitare di attivare una
      // protezione la cui chiave l'utente non ha ancora effettivamente messo al sicuro.
      // Se la biometria è già configurata su questo dispositivo, la Secret Key viene cifrata
      // prima di essere salvata (potrebbe chiedere l'impronta/volto proprio ora).
      // L'envelope del vault in memoria è già quello nuovo (2SKD): saveAndSync() lo salva sia
      // in locale sia su Drive, riusando la stessa logica del salvataggio normale.
      await cacheSecretKeyLocally(pending2SKDSecretKey);
      await saveAndSync();

      document.getElementById('modal-2skd-reveal').classList.add('hidden');
      document.getElementById('settings-2skd-status').textContent = 'Attiva';
      if (btnEnable2SKD) btnEnable2SKD.disabled = true;

      pending2SKDPacked = null;
      pending2SKDSecretKey = null;
      pending2SKDPreviousEnvelope = null;

      UI.showToast("Protezione Secret Key attivata", "success");
    });
  }

  // Se il modal viene chiuso SENZA confermare (X, click fuori), annulla tutto: la mutazione
  // in memoria dell'envelope va disfatta, e nulla va persistito.
  const modal2SKD = document.getElementById('modal-2skd-reveal');
  if (modal2SKD) {
    modal2SKD.addEventListener('click', (e) => {
      const isCloseAction = e.target.closest('.btn-close-modal') || e.target.classList.contains('modal-backdrop');
      if (isCloseAction && pending2SKDPacked) {
        appVault.envelope = pending2SKDPreviousEnvelope;
        pending2SKDPacked = null;
        pending2SKDSecretKey = null;
        pending2SKDPreviousEnvelope = null;
        UI.showToast("Attivazione annullata", "info");
      }
    });
  }

  const btnCopySecretKey = document.getElementById('btn-copy-secret-key');
  if (btnCopySecretKey) {
    btnCopySecretKey.addEventListener('click', async () => {
      const text = document.getElementById('secret-key-display').textContent;
      try {
        await navigator.clipboard.writeText(text);
        UI.showToast("Secret Key copiata", "success");
      } catch (e) {
        UI.showToast("Impossibile copiare automaticamente, seleziona e copia manualmente", "warning");
      }
    });
  }

  // --- 2FA: Sblocco biometrico ---
  const btnEnableBiometric = document.getElementById('btn-enable-biometric');
  if (btnEnableBiometric) {
    btnEnableBiometric.addEventListener('click', async () => {
      if (!appVault.isUnlocked() || !appVault.vaultKeyRaw) {
        UI.showToast("Il vault deve essere sbloccato", "error");
        return;
      }
      try {
        UI.showToast("Segui le istruzioni del dispositivo per la verifica biometrica...", "info");
        await TwoFactor.registerBiometric(appVault.vaultKeyRaw);
        TwoFactor.markFullPasswordAuth();
        await upgradePlaintextSecretKeyToEncrypted();
        UI.showToast("Sblocco biometrico abilitato", "success");
        UI.updateSecuritySettingsUI({
          biometricEnabled: TwoFactor.isBiometricRegistered(),
          totpEnabled: TwoFactor.isTOTPRegistered()
        });
      } catch (err) {
        console.error(err);
        if (err.message === 'PRF_UNSUPPORTED') {
          UI.showToast("Questo dispositivo non supporta lo sblocco biometrico. Usa il codice 2FA come alternativa.", "warning");
          openTotpSetup();
        } else {
          UI.showToast(err.message || "Impossibile abilitare lo sblocco biometrico", "error");
        }
      }
    });
  }

  const btnDisableBiometric = document.getElementById('btn-disable-biometric');
  if (btnDisableBiometric) {
    btnDisableBiometric.addEventListener('click', () => {
      if (!confirm("Disattivare lo sblocco biometrico su questo dispositivo?")) return;
      TwoFactor.disableBiometric();
      UI.showToast("Sblocco biometrico disattivato", "info");
      UI.updateSecuritySettingsUI({
        biometricEnabled: TwoFactor.isBiometricRegistered(),
        totpEnabled: TwoFactor.isTOTPRegistered()
      });
    });
  }

  // --- 2FA: Codice TOTP ---
  const btnEnableTotp = document.getElementById('btn-enable-totp');
  if (btnEnableTotp) {
    btnEnableTotp.addEventListener('click', () => {
      if (!appVault.isUnlocked() || !appVault.vaultKeyRaw) {
        UI.showToast("Il vault deve essere sbloccato", "error");
        return;
      }
      openTotpSetup();
    });
  }

  const btnDisableTotp = document.getElementById('btn-disable-totp');
  if (btnDisableTotp) {
    btnDisableTotp.addEventListener('click', () => {
      if (!confirm("Disattivare il codice 2FA su questo dispositivo?")) return;
      TwoFactor.disableTOTP();
      UI.showToast("Codice 2FA disattivato", "info");
      UI.updateSecuritySettingsUI({
        biometricEnabled: TwoFactor.isBiometricRegistered(),
        totpEnabled: TwoFactor.isTOTPRegistered()
      });
    });
  }

  const btnCopyTotpSecret = document.getElementById('btn-copy-totp-secret');
  if (btnCopyTotpSecret) {
    btnCopyTotpSecret.addEventListener('click', async () => {
      if (!pendingTotpSecret) return;
      try {
        await navigator.clipboard.writeText(pendingTotpSecret);
        UI.showToast("Chiave copiata", "success");
      } catch (e) {
        UI.showToast("Impossibile copiare automaticamente, seleziona e copia manualmente", "warning");
      }
    });
  }

  const formTotpConfirm = document.getElementById('form-totp-confirm');
  if (formTotpConfirm) {
    formTotpConfirm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = document.getElementById('totp-confirm-code').value;
      if (!pendingTotpSecret) {
        UI.showToast("Nessuna configurazione in corso", "error");
        return;
      }
      try {
        await TwoFactor.registerTOTP(pendingTotpSecret, code, appVault.vaultKeyRaw);
        TwoFactor.markFullPasswordAuth();
        pendingTotpSecret = null;
        document.getElementById('modal-totp-setup').classList.add('hidden');
        formTotpConfirm.reset();
        UI.showToast("Codice 2FA configurato con successo", "success");
        UI.updateSecuritySettingsUI({
          biometricEnabled: TwoFactor.isBiometricRegistered(),
          totpEnabled: TwoFactor.isTOTPRegistered()
        });
      } catch (err) {
        console.error(err);
        UI.showToast(err.message || "Codice non valido", "error");
      }
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

        // Adotta subito un'eventuale configurazione OTP salvata su Drive: se presente, anche
        // su QUESTO dispositivo (che magari non ha mai avuto biometria/TOTP/email configurati)
        // la password da sola non basterà più per entrare.
        await adoptRemoteOtpConfigIfPresent();
        
        // Cerca il file del vault su Drive
        const file = await driveClient.findVaultFile();
        if (file) {
          currentVaultFileId = file.id;
          const remoteData = await driveClient.readVaultFile(file.id);
          
          const pwd = prompt("Inserisci la password principale del vault salvato su Google Drive:");
          if (pwd) {
            UI.showScreen('screen-loading');
            try {
              // Verifica la password ed eventualmente avvia la verifica aggiuntiva (se il
              // vault la richiede, localmente o secondo la configurazione appena scaricata da
              // Drive), SENZA decifrare subito il contenuto. persistLocally=true: una volta
              // completata la verifica, il blob va salvato anche in questo browser.
              await unlockBlobWithPasswordAndVerification(pwd, remoteData, true);
            } catch (err) {
              console.error(err);
              UI.showToast(err.message || "Password errata o file non valido", "error");
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
            // Stessa protezione del login normale: se serve una verifica aggiuntiva (locale o
            // secondo la configurazione appena scaricata da Drive), la password da sola non
            // porta subito alla dashboard (mostra invece la schermata di verifica extra).
            await unlockBlobWithPasswordAndVerification(pwd, remoteData, true);
          } catch(e) {
            console.error(e);
            UI.showToast(e.message || "Password errata", "error");
          }
        }
      } else if (appVault.isUnlocked()) {
        // We are already unlocked. We should try to unlock remote data with same password to merge or overwrite.
        // For simplicity in this version, we will overwrite local if remote is newer, or overwrite remote if local is newer.
        // Usually, proper sync requires merging items. Here we just take the newest vault file.
        // A better implementation would unpack remote and compare timestamps.
        
        try {
          // Verify we can open it. Se non abbiamo la password in memoria (sessione sbloccata
          // con biometria/TOTP), usiamo la vaultKey che comunque già abbiamo.
          const tempVault = new Vault();
          if (appPassword) {
            await tempVault.unlock(appPassword, remoteData);
          } else if (appVault.vaultKeyRaw) {
            await tempVault.unlockWithVaultKey(appVault.vaultKeyRaw, remoteData);
          } else {
            throw new Error("Nessuna chiave disponibile per verificare il file remoto");
          }
          
          const localStats = appVault.getStats();
          const remoteStats = tempVault.getStats();
          
          const localTime = new Date(localStats.lastUpdated).getTime();
          const remoteTime = new Date(remoteStats.lastUpdated).getTime();
          
          if (remoteTime > localTime) {
            // Non sostituire mai silenziosamente un vault locale protetto da 2SKD con uno
            // remoto che non lo è: sarebbe un declassamento di sicurezza silenzioso, e la sola
            // differenza di timestamp non è un segnale affidabile abbastanza per farlo senza
            // che l'utente se ne accorga (es. se un caricamento precedente su Drive fosse
            // fallito lasciando lì una copia più vecchia ma con timestamp comunque avanzato).
            if (appVault.isTwoSecretKeyDerivationEnabled() && !tempVault.isTwoSecretKeyDerivationEnabled()) {
              console.warn("Sync automatico da Drive saltato: il vault remoto non ha la protezione 2SKD attiva, quello locale sì.");
              UI.showToast("Trovata su Drive una versione del vault senza la protezione Secret Key: sync automatico saltato per sicurezza. Usa 'Sincronizza ora' per forzare, se sei sicuro.", "warning");
            } else {
              // Replace local
              appVault = tempVault;
              UI.initUI(appVault, driveClient);
              localStorage.setItem(LOCAL_STORAGE_KEY, arrayBufferToBase64(remoteData));
              UI.renderItemList(appVault.getAllItems());
              UI.renderCategories(appVault.getCategories(), null);
              UI.showToast("Vault aggiornato da Drive", "info");
            }
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