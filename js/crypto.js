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

  const vaultKey = await crypto.subtle.importKey(
    "raw", vaultKeyRaw, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, vaultKey, enc.encode(vaultJsonString)
  );

  const ivKey = crypto.getRandomValues(new Uint8Array(12));
  const encryptedVaultKey = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: ivKey }, derivedKey, vaultKeyRaw
  );

  const packed = new Uint8Array(salt.length + ivKey.length + encryptedVaultKey.byteLength + iv.length + encryptedData.byteLength);
  packed.set(salt, 0);
  packed.set(ivKey, salt.length);
  packed.set(new Uint8Array(encryptedVaultKey), salt.length + ivKey.length);
  packed.set(iv, salt.length + ivKey.length + encryptedVaultKey.byteLength);
  packed.set(new Uint8Array(encryptedData), salt.length + ivKey.length + encryptedVaultKey.byteLength + iv.length);

  return { packed, vaultKeyRaw };
}

export async function unpackVault(password, packedData) {
  const salt = packedData.slice(0, 16);
  const ivKey = packedData.slice(16, 28);
  const encryptedVaultKey = packedData.slice(28, 76); // 32 bytes key + 16 bytes auth tag
  const iv = packedData.slice(76, 88);
  const encryptedData = packedData.slice(88);

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

  const vaultKey = await crypto.subtle.importKey(
    "raw", vaultKeyRaw, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]
  );

  const decryptedData = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv }, vaultKey, encryptedData
  );

  const dec = new TextDecoder();
  const vaultJson = dec.decode(decryptedData);

  return { vaultJson, vaultKeyRaw, salt };
}

export function wipeBuffer(buffer) {
  if (buffer) {
    crypto.getRandomValues(buffer);
  }
}
