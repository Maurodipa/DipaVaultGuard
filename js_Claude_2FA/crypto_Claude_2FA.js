// Formato del blob impacchettato:
//
//   FORMATO "v1" (legacy, invariato dall'inizio del progetto):
//   [ salt(16) | ivKey(12) | encryptedVaultKey(48) | iv(12) | encryptedData(resto) ]
//   La vaultKey è protetta con un UNICO segreto: la password principale (PBKDF2).
//
//   FORMATO "2SKD" (Two-Secret Key Derivation, opzionale):
//   [ MAGIC_2SKD(4) | salt(16) | ivKey(12) | encryptedVaultKey(48) | iv(12) | encryptedData(resto) ]
//   Identico al formato v1, ma preceduto da un marcatore fisso di 4 byte, e la vaultKey è
//   protetta da DUE segreti combinati insieme: la password E una Secret Key locale ad alta
//   entropia (mai sincronizzata su Drive). Anche conoscendo la password, senza la Secret Key
//   non si può decifrare nulla — è lo stesso principio usato da 1Password.
//
// Il marcatore MAGIC_2SKD rende i due formati distinguibili senza ambiguità: la probabilità
// che un salt casuale di un blob v1 inizi per coincidenza con questi 4 byte specifici è
// trascurabile (1 su 2^32), quindi possiamo controllare semplicemente i primi 4 byte.
const MAGIC_2SKD = new Uint8Array([0x32, 0x53, 0x4B, 0x44]); // ASCII "2SKD"
const ENVELOPE_LENGTH = 76; // salt(16) + ivKey(12) + encryptedVaultKey(48), invariato nei due formati

function hasMagicPrefix(packedData) {
  // Difesa in profondità: se qualcuno passa per errore un ArrayBuffer grezzo invece di un
  // Uint8Array, packedData[i] e packedData.length restituirebbero silenziosamente `undefined`
  // (nessun errore), facendo fallire questo controllo in modo impossibile da diagnosticare a
  // valle. Normalizziamo qui una volta per tutte.
  const data = packedData instanceof Uint8Array ? packedData : new Uint8Array(packedData);
  if (data.length < MAGIC_2SKD.length) return false;
  for (let i = 0; i < MAGIC_2SKD.length; i++) {
    if (data[i] !== MAGIC_2SKD[i]) return false;
  }
  return true;
}

// Vero se questo blob richiede una Secret Key (oltre alla password) per essere sbloccato.
export function isSecretKeyRequired(packedData) {
  return hasMagicPrefix(packedData);
}

// --- Generazione e codifica della Secret Key ---
// Alfabeto Crockford Base32 (esclude I, L, O, U per evitare ambiguità visive tipo I/1, O/0).
const SECRET_KEY_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function generateSecretKeyRaw() {
  return crypto.getRandomValues(new Uint8Array(16)); // 128 bit di entropia, come la Secret Key di 1Password
}

function bytesToBase32(bytes) {
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    out += SECRET_KEY_ALPHABET[parseInt(bits.substring(i, i + 5), 2)];
  }
  const remainder = bits.length % 5;
  if (remainder !== 0) {
    const lastChunk = bits.substring(bits.length - remainder).padEnd(5, '0');
    out += SECRET_KEY_ALPHABET[parseInt(lastChunk, 2)];
  }
  return out;
}

function base32ToBytes(str) {
  const clean = str.toUpperCase().replace(/[^0-9A-Z]/g, '');
  let bits = '';
  for (const c of clean) {
    const val = SECRET_KEY_ALPHABET.indexOf(c);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

// Formatta la Secret Key grezza in una stringa leggibile tipo "DVG2-XXXXXX-XXXXXX-XXXXXX-XXXXXX"
export function formatSecretKey(rawBytes) {
  const encoded = bytesToBase32(rawBytes);
  const groups = encoded.match(/.{1,6}/g) || [];
  return 'DVG2-' + groups.join('-');
}

// Converte la stringa (con o senza trattini/prefisso) nei byte grezzi originali.
export function parseSecretKey(formatted) {
  const withoutPrefix = formatted.trim().toUpperCase().replace(/^DVG2-?/, '');
  return base32ToBytes(withoutPrefix);
}

// --- Derivazione della chiave che protegge la vaultKey ---

// Formato v1: un solo segreto (la password).
async function deriveKeyFromPasswordOnly(password, salt) {
  const enc = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]
  );
  return await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
    passwordKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}

// Formato 2SKD: combina PBKDF2(password) e HKDF(secretKey) con uno XOR byte a byte, in modo
// che il risultato dipenda in modo inscindibile da ENTRAMBI i segreti — esattamente come fa
// 1Password nel suo design "two-secret key derivation". Nessuno dei due segreti da solo
// permette di ricostruire la chiave finale.
async function deriveKeyFromPasswordAndSecretKey(password, secretKeyRaw, salt) {
  const enc = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const passwordBits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" }, passwordKey, 256
  ));

  const secretMaterial = await crypto.subtle.importKey("raw", secretKeyRaw, { name: "HKDF" }, false, ["deriveBits"]);
  const secretBits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: enc.encode("dipavaultguard-2skd") }, secretMaterial, 256
  ));

  const combined = new Uint8Array(32);
  for (let i = 0; i < 32; i++) combined[i] = passwordBits[i] ^ secretBits[i];

  return await crypto.subtle.importKey("raw", combined, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

// --- Pack / unpack, entrambi i formati ---

// Crea un blob in formato v1 (legacy, un solo segreto). Usato per la creazione di nuovi vault
// e per operazioni che non toccano il formato di protezione della vaultKey.
export async function packVault(password, vaultJsonString, existingVaultKeyRaw = null) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const derivedKey = await deriveKeyFromPasswordOnly(password, salt);

  let vaultKeyRaw = existingVaultKeyRaw;
  if (!vaultKeyRaw) {
    vaultKeyRaw = crypto.getRandomValues(new Uint8Array(32));
  }

  const ivKey = crypto.getRandomValues(new Uint8Array(12));
  const encryptedVaultKey = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: ivKey }, derivedKey, vaultKeyRaw
  ));

  const envelope = { salt, ivKey, encryptedVaultKey, magic: null };
  const packed = await repackVaultData(vaultKeyRaw, vaultJsonString, envelope);

  return { packed, vaultKeyRaw, envelope };
}

// Crea un blob in formato 2SKD (password + Secret Key). Usato quando l'utente attiva
// esplicitamente questa protezione, o cambia la password su un vault che la usa già.
export async function packVault2SKD(password, secretKeyRaw, vaultJsonString, existingVaultKeyRaw = null) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const derivedKey = await deriveKeyFromPasswordAndSecretKey(password, secretKeyRaw, salt);

  let vaultKeyRaw = existingVaultKeyRaw;
  if (!vaultKeyRaw) {
    vaultKeyRaw = crypto.getRandomValues(new Uint8Array(32));
  }

  const ivKey = crypto.getRandomValues(new Uint8Array(12));
  const encryptedVaultKey = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: ivKey }, derivedKey, vaultKeyRaw
  ));

  const envelope = { salt, ivKey, encryptedVaultKey, magic: MAGIC_2SKD };
  const packed = await repackVaultData(vaultKeyRaw, vaultJsonString, envelope);

  return { packed, vaultKeyRaw, envelope };
}

// Legge un blob (di uno dei due formati, rilevato automaticamente) e restituisce i dati in
// chiaro. Se il blob è in formato 2SKD e non viene fornita la Secret Key, lancia un errore
// con messaggio "SECRET_KEY_REQUIRED" (così chi chiama può distinguere questo caso da una
// password sbagliata e proporre all'utente di inserire la Secret Key).
export async function unpackVault(password, packedData, secretKeyRaw = null) {
  const requiresSecretKey = hasMagicPrefix(packedData);
  const body = requiresSecretKey ? packedData.slice(MAGIC_2SKD.length) : packedData;

  const salt = body.slice(0, 16);
  const ivKey = body.slice(16, 28);
  const encryptedVaultKey = body.slice(28, 76);

  let derivedKey;
  if (requiresSecretKey) {
    if (!secretKeyRaw) throw new Error("SECRET_KEY_REQUIRED");
    derivedKey = await deriveKeyFromPasswordAndSecretKey(password, secretKeyRaw, salt);
  } else {
    derivedKey = await deriveKeyFromPasswordOnly(password, salt);
  }

  const vaultKeyRawBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivKey }, derivedKey, encryptedVaultKey
  );
  const vaultKeyRaw = new Uint8Array(vaultKeyRawBuffer);

  const { vaultJson } = await decryptDataPortion(vaultKeyRaw, body);

  return {
    vaultJson,
    vaultKeyRaw,
    envelope: { salt, ivKey, encryptedVaultKey, magic: requiresSecretKey ? MAGIC_2SKD : null }
  };
}

// Verifica la password (ed eventualmente la Secret Key) decifrando SOLO l'involucro, SENZA
// toccare i dati veri e propri del vault. Stessa logica di unpackVault ma senza decifrare il
// contenuto — usata per confermare le credenziali prima di una verifica aggiuntiva (2FA).
export async function unwrapVaultKeyWithPassword(password, packedData, secretKeyRaw = null) {
  const requiresSecretKey = hasMagicPrefix(packedData);
  const body = requiresSecretKey ? packedData.slice(MAGIC_2SKD.length) : packedData;

  const salt = body.slice(0, 16);
  const ivKey = body.slice(16, 28);
  const encryptedVaultKey = body.slice(28, 76);

  let derivedKey;
  if (requiresSecretKey) {
    if (!secretKeyRaw) throw new Error("SECRET_KEY_REQUIRED");
    derivedKey = await deriveKeyFromPasswordAndSecretKey(password, secretKeyRaw, salt);
  } else {
    derivedKey = await deriveKeyFromPasswordOnly(password, salt);
  }

  const vaultKeyRawBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivKey }, derivedKey, encryptedVaultKey
  );
  return new Uint8Array(vaultKeyRawBuffer);
}

// Sblocca il vault avendo direttamente la vaultKey (32 byte) — usato per lo sblocco
// biometrico/TOTP, che non passa mai da password o Secret Key. Format-agnostico: salta
// automaticamente il marcatore 2SKD se presente, senza bisogno di sapere quale formato sia.
export async function unpackVaultWithKey(vaultKeyRaw, packedData) {
  const requiresSecretKey = hasMagicPrefix(packedData);
  const body = requiresSecretKey ? packedData.slice(MAGIC_2SKD.length) : packedData;

  const salt = body.slice(0, 16);
  const ivKey = body.slice(16, 28);
  const encryptedVaultKey = body.slice(28, 76);

  const { vaultJson } = await decryptDataPortion(vaultKeyRaw, body);

  return {
    vaultJson,
    envelope: { salt, ivKey, encryptedVaultKey, magic: requiresSecretKey ? MAGIC_2SKD : null }
  };
}

async function decryptDataPortion(vaultKeyRaw, body) {
  const iv = body.slice(76, 88);
  const encryptedData = body.slice(88);

  const vaultKey = await crypto.subtle.importKey(
    "raw", vaultKeyRaw, { name: "AES-GCM" }, false, ["decrypt"]
  );

  const decryptedData = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv }, vaultKey, encryptedData
  );

  const dec = new TextDecoder();
  return { vaultJson: dec.decode(decryptedData) };
}

// Ri-cifra SOLO i dati del vault con la vaultKey esistente, riusando l'involucro (envelope)
// già presente, senza rifare la costosa derivazione. Preserva automaticamente il marcatore
// 2SKD se l'envelope lo ha (envelope.magic), così un vault 2SKD resta 2SKD a ogni salvataggio.
export async function repackVaultData(vaultKeyRaw, vaultJsonString, envelope) {
  const enc = new TextEncoder();
  const vaultKey = await crypto.subtle.importKey(
    "raw", vaultKeyRaw, { name: "AES-GCM" }, false, ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedData = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, vaultKey, enc.encode(vaultJsonString)
  ));

  const { salt, ivKey, encryptedVaultKey, magic } = envelope;
  const prefixLen = magic ? magic.length : 0;
  const packed = new Uint8Array(prefixLen + ENVELOPE_LENGTH + iv.length + encryptedData.byteLength);

  let offset = 0;
  if (magic) {
    packed.set(magic, 0);
    offset = magic.length;
  }
  packed.set(salt, offset);
  packed.set(ivKey, offset + salt.length);
  packed.set(encryptedVaultKey, offset + salt.length + ivKey.length);
  packed.set(iv, offset + ENVELOPE_LENGTH);
  packed.set(encryptedData, offset + ENVELOPE_LENGTH + iv.length);

  return packed;
}

export function wipeBuffer(buffer) {
  if (buffer) {
    crypto.getRandomValues(buffer);
  }
}

// --- Helper generici usati dal modulo 2FA (twofactor.js) per proteggere una copia
// della vaultKey con una chiave derivata da biometria (WebAuthn PRF) o da un segreto TOTP ---

export async function aesEncryptRaw(keyRaw, dataBytes) {
  const key = await crypto.subtle.importKey("raw", keyRaw, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, dataBytes));
  return { iv, ciphertext };
}

export async function aesDecryptRaw(keyRaw, iv, ciphertext) {
  const key = await crypto.subtle.importKey("raw", keyRaw, { name: "AES-GCM" }, false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new Uint8Array(plaintext);
}

// Deriva 32 byte "puliti" (chiave AES-256) da materiale segreto grezzo (es. output PRF di
// WebAuthn o segreto TOTP) tramite HKDF-SHA256, con una stringa "info" per separare i contesti
// d'uso. Non riusiamo mai il materiale grezzo direttamente come chiave.
export async function hkdfDeriveBits(rawMaterial, infoString, lengthBits = 256) {
  const material = await crypto.subtle.importKey("raw", rawMaterial, { name: "HKDF" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new TextEncoder().encode(infoString) },
    material, lengthBits
  );
  return new Uint8Array(bits);
}
