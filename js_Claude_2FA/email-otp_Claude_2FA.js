// Modulo di verifica OTP via email, usato come ulteriore passaggio obbligatorio quando si
// sblocca il vault con la sola password (dopo che biometria e/o TOTP sono già stati
// configurati su questo dispositivo). Non essendoci un backend proprio, l'invio dell'email
// avviene direttamente dal browser tramite EmailJS (https://www.emailjs.com/), un servizio
// pensato apposta per siti statici client-side.
//
// Il codice OTP viene generato qui nel browser e tenuto SOLO in memoria (mai salvato su
// disco): la verifica confronta quanto digitato dall'utente con questo valore. Questo NON è
// un fattore crittografico come la biometria (i dati del vault sono già stati decifrati in
// memoria a questo punto, essendo la password corretta) — è un ostacolo aggiuntivo reale
// contro chi conosce/digita la password ma non ha accesso alla casella email configurata.

const SETTINGS_KEY = 'dipavaultguard_email_otp_config';
const OTP_VALIDITY_MS = 10 * 60 * 1000; // 10 minuti
const MAX_ATTEMPTS = 5;

let pendingOtp = null; // { code, expiresAt, attempts }

export function getConfig() {
  try {
    return JSON.parse(localStorage.getItem(SETTINGS_KEY) || 'null');
  } catch (e) {
    return null;
  }
}

export function isEmailOtpConfigured() {
  const cfg = getConfig();
  return !!(cfg && cfg.serviceId && cfg.templateId && cfg.publicKey && cfg.recipientEmail);
}

export function saveConfig({ serviceId, templateId, publicKey, recipientEmail }) {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify({ serviceId, templateId, publicKey, recipientEmail }));
}

export function clearConfig() {
  localStorage.removeItem(SETTINGS_KEY);
}

function generateCode() {
  const rnd = crypto.getRandomValues(new Uint32Array(1))[0];
  return (rnd % 1000000).toString().padStart(6, '0');
}

function ensureEmailJsReady() {
  if (typeof emailjs === 'undefined') {
    throw new Error('Libreria EmailJS non caricata (controlla la connessione e ricarica la pagina).');
  }
}

// Genera un nuovo codice, lo invia via email con EmailJS e lo tiene in memoria in attesa di
// verifica. Lancia un errore se l'invio fallisce (es. dispositivo offline, configurazione
// errata): in quel caso l'app dovrebbe proporre il TOTP come alternativa, se disponibile.
//
// NOTA sui nomi dei parametri: "passcode", "time" ed "email" corrispondono al template
// predefinito "One-Time Password" fornito da EmailJS. Se usi un template diverso con nomi di
// variabili differenti, aggiorna questi nomi di conseguenza (in particolare il campo "To
// Email" nelle impostazioni del template EmailJS deve corrispondere esattamente alla chiave
// usata qui per il destinatario, altrimenti l'invio fallisce senza un errore chiaro).
export async function sendOtp() {
  const cfg = getConfig();
  if (!cfg || !isEmailOtpConfigured()) {
    throw new Error('Verifica via email non configurata.');
  }
  ensureEmailJsReady();

  const code = generateCode();
  const expiresAt = Date.now() + OTP_VALIDITY_MS;
  pendingOtp = { code, expiresAt, attempts: 0 };

  try {
    await emailjs.send(cfg.serviceId, cfg.templateId, {
      passcode: code,
      time: formatExpiryTime(expiresAt),
      email: cfg.recipientEmail
    }, cfg.publicKey);
  } catch (e) {
    console.error('EmailJS send error:', e);
    pendingOtp = null;
    throw new Error('Invio email non riuscito. Controlla la connessione internet e la configurazione.');
  }

  return true;
}

function formatExpiryTime(timestampMs) {
  return new Date(timestampMs).toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' });
}

// Invia un'email di prova (senza impostare un OTP "in attesa" reale), usata dal pulsante
// "Invia email di prova" nelle impostazioni per verificare che la configurazione funzioni.
export async function sendTestEmail() {
  const cfg = getConfig();
  if (!cfg || !isEmailOtpConfigured()) {
    throw new Error('Compila tutti i campi prima di inviare una prova.');
  }
  ensureEmailJsReady();

  const testCode = generateCode();
  try {
    await emailjs.send(cfg.serviceId, cfg.templateId, {
      passcode: testCode,
      time: formatExpiryTime(Date.now() + OTP_VALIDITY_MS),
      email: cfg.recipientEmail
    }, cfg.publicKey);
  } catch (e) {
    console.error('EmailJS test send error:', e);
    throw new Error('Invio non riuscito. Controlla Service ID, Template ID e Public Key.');
  }

  return true;
}

export function hasPendingOtp() {
  return !!pendingOtp;
}

export function verifyOtp(inputCode) {
  if (!pendingOtp) {
    throw new Error('Nessun codice in attesa. Richiedine uno nuovo.');
  }
  if (Date.now() > pendingOtp.expiresAt) {
    pendingOtp = null;
    throw new Error('Codice scaduto. Richiedine uno nuovo.');
  }
  pendingOtp.attempts++;
  if (pendingOtp.attempts > MAX_ATTEMPTS) {
    pendingOtp = null;
    throw new Error('Troppi tentativi falliti. Richiedi un nuovo codice.');
  }

  const clean = (inputCode || '').trim();
  if (clean !== pendingOtp.code) {
    throw new Error('Codice non corretto.');
  }

  pendingOtp = null;
  return true;
}

// Da chiamare se l'utente annulla la verifica: evita che un vecchio codice resti valido oltre
// il tentativo per cui era stato generato.
export function clearPendingOtp() {
  pendingOtp = null;
}
