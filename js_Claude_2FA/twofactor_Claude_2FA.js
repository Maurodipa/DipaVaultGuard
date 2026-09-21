// Modulo di secondo fattore (2FA) per DipaVaultGuard.
//
// PRINCIPIO CHIAVE: questo NON è un semplice "cancello" a livello di interfaccia.
// La vaultKey (la chiave che cifra davvero i dati del vault) viene protetta con una copia
// aggiuntiva, cifrata con una chiave derivata dal secondo fattore:
//   - Biometria: WebAuthn con estensione PRF. Il segreto vive nell'hardware sicuro del
//     dispositivo (es. StrongBox/TEE su Android) e non è mai estraibile da JavaScript:
//     solo il suo OUTPUT (dato un determinato input) può essere richiesto, e solo dopo una
//     verifica utente riuscita (impronta/volto) ogni volta. Questo è un fattore crittografico
//     reale.
//   - TOTP (fallback per dispositivi senza supporto PRF): qui il segreto condiviso deve
//     necessariamente essere presente anche in questo browser (altrimenti non potremmo
//     verificare il codice a 6 cifre), quindi rispetto alla biometria è una protezione più
//     debole se qualcuno riuscisse a estrarre i dati salvati in questo browser. Resta
//     comunque un secondo fattore reale, sia perché la chiave del vault viene wrappata con
//     esso (non è solo un controllo a schermo), sia perché protegge dall'accesso "casuale"
//     (es. telefono sbloccato trovato da terzi) e richiede il possesso dell'app authenticator
//     abbinata.
//
// In entrambi i casi, il file del vault sincronizzato su Google Drive NON viene toccato da
// questo modulo: resta protetto solo dalla password principale (envelope in crypto.js), quindi
// il ripristino su un nuovo dispositivo richiede sempre la password.

import { aesEncryptRaw, aesDecryptRaw, hkdfDeriveBits } from './crypto_Claude_2FA.js';

const BIOMETRIC_KEY = 'dipavaultguard_biometric';
const TOTP_KEY = 'dipavaultguard_totp';
let cachedPrfSecretKey = null; // Cache temporanea per bypassare bug Android

// --- DEBUG OVERLAY ---
export function debugLog(msg) {
  let div = document.getElementById('debug-log-overlay');
  if (!div) {
    div = document.createElement('div');
    div.id = 'debug-log-overlay';
    div.style.position = 'fixed';
    div.style.top = '0';
    div.style.left = '0';
    div.style.width = '100%';
    div.style.height = '40%';
    div.style.backgroundColor = 'rgba(0,0,0,0.85)';
    div.style.color = 'lime';
    div.style.zIndex = '99999';
    div.style.overflowY = 'auto';
    div.style.fontSize = '12px';
    div.style.padding = '10px';
    div.style.pointerEvents = 'none';
    document.body.appendChild(div);
  }
  const time = new Date().toISOString().split('T')[1].slice(0, -1);
  div.innerHTML += '<div>[' + time + '] ' + msg + '</div>';
  div.scrollTop = div.scrollHeight;
  console.log('[DEBUG]', msg);
}

// --- WAIT FOR WEBAUTHN IDLE (KIMI METHOD) ---
async function waitForWebAuthnIdle() {
  debugLog('Inizio attesa WebAuthn (Kimi polling)...');
  let retries = 0;
  while (retries < 20) {
    const ac = new AbortController();
    try {
      const p = navigator.credentials.get({
        publicKey: {
          challenge: new Uint8Array(16),
          allowCredentials: []
        },
        signal: ac.signal
      });
      ac.abort();
      await p;
      debugLog('Polling: get() risolta (inatteso).');
      break; 
    } catch (e) {
      if (e.name === 'AbortError') {
        debugLog('Polling: AbortError ricevuto -> WebAuthn è LIBERO!');
        return;
      }
      if (e.message && e.message.includes('pending')) {
        debugLog('Polling: Ancora pending... attesa 300ms (retry ' + retries + ')');
      } else {
        debugLog('Polling: Errore diverso: ' + e.name);
      }
    }
    await new Promise(r => setTimeout(r, 300));
    retries++;
  }
  debugLog('Fine polling (timeout o libero).');
}
const LAST_FULL_AUTH_KEY = 'dipavaultguard_last_full_auth';
const MAX_DAYS_WITHOUT_PASSWORD = 7;

const RP_NAME = 'DipaVaultGuard';
// Salt fisso per la valutazione PRF: serve solo a separare il contesto d'uso, non è un segreto.
const PRF_SALT = new TextEncoder().encode('dipavaultguard-prf-salt-v1');
// Salt PRF distinto, usato SOLO per cifrare la Secret Key del 2SKD in localStorage — mai per
// la vaultKey. Riusa la STESSA credenziale biometrica già registrata (nessuna nuova
// registrazione richiesta), ma con un salt diverso il valore PRF ottenuto è completamente
// diverso e indipendente da quello usato per la vaultKey (proprietà standard delle PRF).
const PRF_SALT_SECRET_KEY = new TextEncoder().encode('dipavaultguard-prf-salt-secretkey-v1');

// ---------------------------------------------------------------------------
// Tracciamento "richiedi password completa ogni tot giorni"
// ---------------------------------------------------------------------------

export function markFullPasswordAuth() {
  localStorage.setItem(LAST_FULL_AUTH_KEY, Date.now().toString());
}

export function isFullPasswordAuthRequired(maxDays = MAX_DAYS_WITHOUT_PASSWORD) {
  const last = localStorage.getItem(LAST_FULL_AUTH_KEY);
  if (!last) return true;
  const elapsedMs = Date.now() - parseInt(last, 10);
  return elapsedMs > maxDays * 24 * 60 * 60 * 1000;
}

export function daysSinceLastFullAuth() {
  const last = localStorage.getItem(LAST_FULL_AUTH_KEY);
  if (!last) return null;
  return Math.floor((Date.now() - parseInt(last, 10)) / (24 * 60 * 60 * 1000));
}

// ---------------------------------------------------------------------------
// Stato di registrazione
// ---------------------------------------------------------------------------

export function isBiometricRegistered() {
  return !!localStorage.getItem(BIOMETRIC_KEY);
}

export function isTOTPRegistered() {
  return !!localStorage.getItem(TOTP_KEY);
}

// Un metodo rapido (biometria o TOTP) è utilizzabile ORA solo se registrato E se non sono
// passati più di MAX_DAYS_WITHOUT_PASSWORD giorni dall'ultima volta che è stata digitata
// la password completa.
export function canUseQuickUnlock() {
  return (isBiometricRegistered() || isTOTPRegistered()) && !isFullPasswordAuthRequired();
}

export function disableBiometric() {
  localStorage.removeItem(BIOMETRIC_KEY);
}

export function disableTOTP() {
  localStorage.removeItem(TOTP_KEY);
}

// Da chiamare quando la vaultKey cambia in modo che le vecchie registrazioni non abbiano più
// senso (es. reset completo del vault locale).
export function clearAllSecondFactors() {
  localStorage.removeItem(BIOMETRIC_KEY);
  localStorage.removeItem(TOTP_KEY);
  localStorage.removeItem(LAST_FULL_AUTH_KEY);
}

// ---------------------------------------------------------------------------
// Biometria (WebAuthn + estensione PRF)
// ---------------------------------------------------------------------------

export async function isPlatformAuthenticatorAvailable() {
  if (!window.PublicKeyCredential || !PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
    return false;
  }
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch (e) {
    return false;
  }
}

// Registra una credenziale biometrica e la usa per proteggere (wrappare) la vaultKey fornita.
// Lancia un errore chiaro se il dispositivo non supporta l'estensione PRF (in quel caso l'app
// dovrebbe proporre la configurazione TOTP come alternativa).
export async function registerBiometric(vaultKeyRaw) {
  debugLog('Inizio registerBiometric');
  if (!window.PublicKeyCredential) {
    debugLog('WebAuthn non supportato');
    throw new Error('WebAuthn non è supportato su questo browser.');
  }

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));

  let credential;
  try {
    debugLog('Chiamata a navigator.credentials.create()...');
    credential = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { name: RP_NAME },
        user: { id: userId, name: 'vault-owner', displayName: 'Titolare del vault' },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' },   // ES256
          { alg: -257, type: 'public-key' }  // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'preferred'
        },
        timeout: 60000,
        extensions: { 
          prf: { 
            eval: { 
              first: PRF_SALT,
              second: PRF_SALT_SECRET_KEY
            } 
          } 
        }
      }
    });
    debugLog('create() successo!');
  } catch (e) {
    debugLog('Errore in create(): ' + e.name + ' - ' + e.message);
    throw new Error('Errore biometria: ' + (e.name || 'Sconosciuto') + ' - ' + (e.message || ''));
  }

  if (!credential) {
    debugLog('Nessuna credenziale restituita');
    throw new Error('Registrazione biometrica annullata.');
  }

  const createExt = credential.getClientExtensionResults ? credential.getClientExtensionResults() : {};
  if (!createExt || !createExt.prf || !createExt.prf.enabled) {
    debugLog('PRF non abilitato nei risultati di create()');
    throw new Error('PRF_UNSUPPORTED');
  }

  debugLog('Controllo se PRF è stato valutato in create()...');
  let prfBits;
  if (createExt.prf.results && createExt.prf.results.first) {
    debugLog('Risultati PRF ricevuti direttamente da create()! Salto get().');
    prfBits = new Uint8Array(createExt.prf.results.first);
    if (createExt.prf.results.second) {
      cachedPrfSecretKey = new Uint8Array(createExt.prf.results.second);
      debugLog('Cache PRF Secret Key impostata con successo.');
    }
  } else {
    debugLog('Risultati PRF non presenti, tento get()...');
    debugLog('Inizio Kimi polling workaround...');
    await waitForWebAuthnIdle();
    
    try {
      debugLog('Chiamata a evalPrfWithAssertion()...');
      prfBits = await evalPrfWithAssertion(credential.rawId);
      debugLog('evalPrfWithAssertion successo!');
    } catch (e) {
      debugLog('Errore evalPrfWithAssertion: ' + e.name + ' - ' + e.message);
      throw new Error('Errore durante valutazione PRF: ' + (e.name || 'Sconosciuto') + ' - ' + (e.message || ''));
    }
  }
  
  if (!prfBits) {
    debugLog('Nessun bit PRF ritornato');
    throw new Error('PRF_UNSUPPORTED');
  }

  debugLog('Derivazione chiavi in corso...');
  const wrappingKeyRaw = await hkdfDeriveBits(prfBits, 'dipavaultguard-biometric-wrap');
  const { iv, ciphertext } = await aesEncryptRaw(wrappingKeyRaw, vaultKeyRaw);

  const record = {
    credentialId: bufferToBase64(credential.rawId),
    iv: bufferToBase64(iv),
    wrapped: bufferToBase64(ciphertext)
  };
  localStorage.setItem(BIOMETRIC_KEY, JSON.stringify(record));
  debugLog('Registrazione completata con successo!');
  return true;
}

async function evalPrfWithAssertion(credentialRawId, salt = PRF_SALT) {
  const req = {
    publicKey: {
      rpId: window.location.hostname,
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      userVerification: 'required',
      extensions: { prf: { eval: { first: salt } } }
    }
  };
  
  if (credentialRawId) {
    // BUGFIX ANDROID CHROME: il bridge JNI di Android va in crash silente (hang)
    // se passiamo allowCredentials assieme all'estensione PRF. 
    // Su Android omettiamo allowCredentials forzando la tendina "Scegli passkey"
    // che miracolosamente aggira il bug di sistema.
    const isAndroid = /Android/i.test(navigator.userAgent);
    if (!isAndroid) {
      let idBuffer = credentialRawId;
      if (credentialRawId instanceof Uint8Array) {
        idBuffer = credentialRawId.buffer.slice(
          credentialRawId.byteOffset, 
          credentialRawId.byteOffset + credentialRawId.byteLength
        );
      }
      req.publicKey.allowCredentials = [{ id: idBuffer, type: 'public-key' }];
    } else {
      debugLog('Android rilevato: ometto allowCredentials per evitare l\'hang di sistema.');
    }
  }
  
  debugLog('Chiamata a get() con rpId: ' + req.publicKey.rpId);
  const assertion = await navigator.credentials.get(req);
  if (!assertion) return null;
  const ext = assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {};
  const results = ext && ext.prf && ext.prf.results;
  return results && results.first ? new Uint8Array(results.first) : null;
}

// Sblocca il vault tramite biometria: chiede l'impronta/volto, recupera l'output PRF e
// svincola la vaultKey precedentemente wrappata. Restituisce la vaultKey grezza (Uint8Array).
export async function unlockWithBiometric() {
  debugLog('Inizio unlockWithBiometric');
  const recordRaw = localStorage.getItem(BIOMETRIC_KEY);
  if (!recordRaw) {
    debugLog('Errore: record non trovato in localStorage');
    throw new Error('Sblocco biometrico non configurato su questo dispositivo.');
  }
  const record = JSON.parse(recordRaw);

  const credentialId = base64ToBuffer(record.credentialId);
  debugLog('Chiamata a evalPrfWithAssertion per sblocco vault...');
  
  // Aggiungiamo un timeout di sicurezza di 10 secondi per vedere se la promise pende per sempre
  const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error('TIMEOUT_GET')), 10000));
  
  let prfBits;
  try {
    prfBits = await Promise.race([
      evalPrfWithAssertion(credentialId),
      timeoutPromise
    ]);
    debugLog('evalPrfWithAssertion sblocco completato!');
  } catch (e) {
    debugLog('Errore in evalPrfWithAssertion sblocco: ' + e.message);
    throw e;
  }

  if (!prfBits) {
    debugLog('Errore: prfBits è nullo');
    throw new Error('Verifica biometrica non riuscita o annullata.');
  }

  debugLog('Derivazione chiavi di sblocco in corso...');
  const wrappingKeyRaw = await hkdfDeriveBits(prfBits, 'dipavaultguard-biometric-wrap');
  const vaultKeyRaw = await aesDecryptRaw(
    wrappingKeyRaw,
    base64ToBuffer(record.iv),
    base64ToBuffer(record.wrapped)
  );
  debugLog('Sblocco completato con successo!');
  return vaultKeyRaw;
}

// ---------------------------------------------------------------------------
// Cifratura della Secret Key (2SKD) tramite biometria
// ---------------------------------------------------------------------------
// La Secret Key va comunque tenuta in locale per non doverla ridigitare a ogni sblocco, ma
// non c'è motivo che sieda in localStorage in chiaro se questo dispositivo ha già una
// credenziale biometrica: la cifriamo con una chiave derivata dallo stesso meccanismo PRF
// usato per la vaultKey (stessa credenziale, salt diverso), così un accesso diretto a
// localStorage (es. DevTools) non basta più a leggerla: serve anche il sensore biometrico.

export async function isBiometricEncryptionAvailable() {
  return isBiometricRegistered();
}

// Cifra la stringa della Secret Key. Richiede che la biometria sia già registrata su questo
// dispositivo (altrimenti lancia un errore: il chiamante dovrebbe salvarla in chiaro come
// ripiego in quel caso). Chiede una verifica biometrica per calcolare la chiave di cifratura.
export async function encryptSecretKeyWithBiometric(secretKeyFormatted) {
  const recordRaw = localStorage.getItem(BIOMETRIC_KEY);
  if (!recordRaw) throw new Error('Biometria non configurata su questo dispositivo.');
  const record = JSON.parse(recordRaw);

  const credentialId = base64ToBuffer(record.credentialId);

  let prfBits;
  if (cachedPrfSecretKey) {
    debugLog('Uso cache PRF per la Secret Key per bypassare bug Android!');
    prfBits = cachedPrfSecretKey;
    cachedPrfSecretKey = null;
  } else {
    debugLog('Pausa di 1000ms prima di cifrare la Secret Key (Android workaround)...');
    await new Promise(r => setTimeout(r, 1000));

    debugLog('Chiamata a evalPrfWithAssertion per la Secret Key...');
    prfBits = await evalPrfWithAssertion(credentialId, PRF_SALT_SECRET_KEY);
    if (!prfBits) throw new Error('Verifica biometrica non riuscita o annullata.');
    debugLog('evalPrfWithAssertion per Secret Key completato!');
  }

  const wrappingKeyRaw = await hkdfDeriveBits(prfBits, 'dipavaultguard-secretkey-wrap');
  const { iv, ciphertext } = await aesEncryptRaw(wrappingKeyRaw, new TextEncoder().encode(secretKeyFormatted));

  return { iv: bufferToBase64(iv), wrapped: bufferToBase64(ciphertext) };
}

// Decifra un record { iv, wrapped } prodotto da encryptSecretKeyWithBiometric, chiedendo di
// nuovo la verifica biometrica per ricostruire la stessa chiave.
export async function decryptSecretKeyWithBiometric(encryptedRecord) {
  const recordRaw = localStorage.getItem(BIOMETRIC_KEY);
  if (!recordRaw) throw new Error('Biometria non configurata su questo dispositivo: impossibile decifrare la Secret Key salvata.');
  const record = JSON.parse(recordRaw);

  const credentialId = base64ToBuffer(record.credentialId);
  const prfBits = await evalPrfWithAssertion(credentialId, PRF_SALT_SECRET_KEY);
  if (!prfBits) throw new Error('Verifica biometrica non riuscita o annullata.');

  const wrappingKeyRaw = await hkdfDeriveBits(prfBits, 'dipavaultguard-secretkey-wrap');
  const plaintext = await aesDecryptRaw(
    wrappingKeyRaw,
    base64ToBuffer(encryptedRecord.iv),
    base64ToBuffer(encryptedRecord.wrapped)
  );
  return new TextDecoder().decode(plaintext);
}

// ---------------------------------------------------------------------------
// TOTP (fallback per dispositivi senza supporto PRF) — RFC 6238 / RFC 4226
// ---------------------------------------------------------------------------

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(bytes) {
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  let output = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    output += BASE32_ALPHABET[parseInt(bits.substring(i, i + 5), 2)];
  }
  const remainder = bits.length % 5;
  if (remainder !== 0) {
    const lastChunk = bits.substring(bits.length - remainder).padEnd(5, '0');
    output += BASE32_ALPHABET[parseInt(lastChunk, 2)];
  }
  return output;
}

function base32Decode(str) {
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const c of clean) {
    const val = BASE32_ALPHABET.indexOf(c);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

export function generateTOTPSecret(byteLength = 20) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return base32Encode(bytes);
}

export function formatSecretForDisplay(secretBase32) {
  return secretBase32.match(/.{1,4}/g).join(' ');
}

export function getTOTPUri(secretBase32, accountLabel = 'vault', issuer = 'DipaVaultGuard') {
  const label = encodeURIComponent(`${issuer}:${accountLabel}`);
  const params = `secret=${secretBase32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  return `otpauth://totp/${label}?${params}`;
}

async function hotp(secretBytes, counter) {
  const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  // Contatore a 64 bit big-endian (i primi 4 byte restano a 0 per contatori realistici)
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);
  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBuf));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return (binCode % 1000000).toString().padStart(6, '0');
}

async function totpAt(secretBase32, forTimeMs, timeStepSeconds = 30) {
  const counter = Math.floor(forTimeMs / 1000 / timeStepSeconds);
  const secretBytes = base32Decode(secretBase32);
  return hotp(secretBytes, counter);
}

// Verifica un codice a 6 cifre tollerando una finestra di ±30s per compensare piccoli
// disallineamenti dell'orologio tra dispositivo e app authenticator.
export async function verifyTOTPCode(secretBase32, code, windowSteps = 1) {
  const cleanCode = (code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(cleanCode)) return false;
  const now = Date.now();
  for (let w = -windowSteps; w <= windowSteps; w++) {
    const candidate = await totpAt(secretBase32, now + w * 30000);
    if (candidate === cleanCode) return true;
  }
  return false;
}

async function totpSecretToWrappingKey(secretBase32) {
  const secretBytes = base32Decode(secretBase32);
  return await hkdfDeriveBits(secretBytes, 'dipavaultguard-totp-wrap');
}

// Registra il TOTP: verifica che il codice inserito sia corretto (prova che l'utente ha
// davvero configurato l'app authenticator con questo segreto) e poi usa il segreto per
// wrappare la vaultKey.
export async function registerTOTP(secretBase32, code, vaultKeyRaw) {
  const valid = await verifyTOTPCode(secretBase32, code);
  if (!valid) {
    throw new Error('Codice non valido. Verifica l\'ora del dispositivo e riprova.');
  }

  const wrappingKeyRaw = await totpSecretToWrappingKey(secretBase32);
  const { iv, ciphertext } = await aesEncryptRaw(wrappingKeyRaw, vaultKeyRaw);

  const record = {
    secret: secretBase32,
    iv: bufferToBase64(iv),
    wrapped: bufferToBase64(ciphertext)
  };
  localStorage.setItem(TOTP_KEY, JSON.stringify(record));
  return true;
}

// Sblocca il vault tramite codice TOTP: verifica il codice e svincola la vaultKey.
export async function unlockWithTOTP(code) {
  const recordRaw = localStorage.getItem(TOTP_KEY);
  if (!recordRaw) throw new Error('Sblocco con codice 2FA non configurato su questo dispositivo.');
  const record = JSON.parse(recordRaw);

  const valid = await verifyTOTPCode(record.secret, code);
  if (!valid) throw new Error('Codice 2FA errato.');

  const wrappingKeyRaw = await totpSecretToWrappingKey(record.secret);
  const vaultKeyRaw = await aesDecryptRaw(
    wrappingKeyRaw,
    base64ToBuffer(record.iv),
    base64ToBuffer(record.wrapped)
  );
  return vaultKeyRaw;
}

// Verifica un codice TOTP contro il segreto già registrato su questo dispositivo, SENZA
// svincolare la vaultKey. Usata come verifica aggiuntiva pura (es. dopo il percorso password,
// quando la vaultKey è già nota per altra via e serve solo confermare il possesso dell'app
// authenticator).
export async function verifyRegisteredTOTPCode(code) {
  const recordRaw = localStorage.getItem(TOTP_KEY);
  if (!recordRaw) throw new Error('Codice 2FA non configurato su questo dispositivo.');
  const record = JSON.parse(recordRaw);
  const valid = await verifyTOTPCode(record.secret, code);
  if (!valid) throw new Error('Codice 2FA errato.');
  return true;
}

// ---------------------------------------------------------------------------
// Helper Base64 <-> ArrayBuffer (per salvare in localStorage, che accetta solo stringhe)
// ---------------------------------------------------------------------------

function bufferToBase64(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return window.btoa(binary);
}

function base64ToBuffer(base64) {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
