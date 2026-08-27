// Formato del blob impacchettato (invariato):
// [ salt(16) | ivKey(12) | encryptedVaultKey(48 = 32 chiave + 16 tag) | iv(12) | encryptedData(resto) ]
// I primi 76 byte ("envelope") sono l'involucro che protegge la vaultKey con la password
// principale (PBKDF2 + AES-GCM). Gli ultimi byte sono i dati del vault cifrati con la vaultKey.
// Poiché la vaultKey resta stabile nel tempo (viene riusata tra un salvataggio e l'altro),
// possiamo ri-cifrare i soli dati senza dover rifare la derivazione PBKDF2 (costosa) ogni volta,
// e possiamo anche sbloccare il vault avendo direttamente la vaultKey invece della password
// (es. dopo uno sblocco biometrico/TOTP che sblocca la vaultKey in un modo diverso).

const ENVELOPE_LENGTH = 76; // salt(16) + ivKey(12) + encryptedVaultKey(48)

export async function packVault(password, vaultJsonString, existingVaultKeyRaw = null) {
  const enc = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]
  );

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const derivedKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
    passwordKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );

  let vaultKeyRaw = existingVaultKeyRaw;
  if (!vaultKeyRaw) {
    vaultKeyRaw = crypto.getRandomValues(new Uint8Array(32));
  }

  const ivKey = crypto.getRandomValues(new Uint8Array(12));
  const encryptedVaultKey = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: ivKey }, derivedKey, vaultKeyRaw
  ));

  const envelope = { salt, ivKey, encryptedVaultKey };
  const packed = await repackVaultData(vaultKeyRaw, vaultJsonString, envelope);

  return { packed, vaultKeyRaw, envelope };
}

export async function unpackVault(password, packedData) {
  const salt = packedData.slice(0, 16);
  const ivKey = packedData.slice(16, 28);
  const encryptedVaultKey = packedData.slice(28, 76); // 32 bytes key + 16 bytes auth tag

  const enc = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]
  );

  const derivedKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
    passwordKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );

  const vaultKeyRawBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivKey }, derivedKey, encryptedVaultKey
  );
  const vaultKeyRaw = new Uint8Array(vaultKeyRawBuffer);

  const { vaultJson } = await decryptDataPortion(vaultKeyRaw, packedData);

  return { vaultJson, vaultKeyRaw, envelope: { salt, ivKey, encryptedVaultKey } };
}

// Sblocca il vault avendo direttamente la vaultKey (32 byte), senza bisogno della password.
// Usato per lo sblocco biometrico/TOTP: quel percorso recupera la vaultKey in un modo diverso
// (svincolando una copia protetta dal secondo fattore), poi qui semplicemente si decifrano
// i dati come al solito. L'involucro protetto dalla password (byte 0-75) viene comunque
// preservato/restituito così com'è: resta valido, la password principale continua a funzionare.
export async function unpackVaultWithKey(vaultKeyRaw, packedData) {
  const salt = packedData.slice(0, 16);
  const ivKey = packedData.slice(16, 28);
  const encryptedVaultKey = packedData.slice(28, 76);

  const { vaultJson } = await decryptDataPortion(vaultKeyRaw, packedData);

  return { vaultJson, envelope: { salt, ivKey, encryptedVaultKey } };
}

async function decryptDataPortion(vaultKeyRaw, packedData) {
  const iv = packedData.slice(76, 88);
  const encryptedData = packedData.slice(88);

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
// già presente (salt/ivKey/encryptedVaultKey), senza rifare la costosa derivazione PBKDF2.
// Questo è ciò che permette di salvare le modifiche al vault anche quando si è sbloccato
// tramite biometria/TOTP (cioè senza avere la password principale in memoria).
export async function repackVaultData(vaultKeyRaw, vaultJsonString, envelope) {
  const enc = new TextEncoder();
  const vaultKey = await crypto.subtle.importKey(
    "raw", vaultKeyRaw, { name: "AES-GCM" }, false, ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedData = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, vaultKey, enc.encode(vaultJsonString)
  ));

  const { salt, ivKey, encryptedVaultKey } = envelope;
  const packed = new Uint8Array(ENVELOPE_LENGTH + iv.length + encryptedData.byteLength);
  packed.set(salt, 0);
  packed.set(ivKey, salt.length);
  packed.set(encryptedVaultKey, salt.length + ivKey.length);
  packed.set(iv, ENVELOPE_LENGTH);
  packed.set(encryptedData, ENVELOPE_LENGTH + iv.length);

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
