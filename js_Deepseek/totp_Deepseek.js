// js/totp.js
// Implementazione TOTP con HMAC-SHA1 e base32

const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateTOTPSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return base32Encode(bytes);
}

export function getTOTPURL(secret, issuer = 'DipaVaultGuard', accountName = 'user') {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

export async function generateTOTP(secret, counter = null) {
  if (counter === null) {
    counter = Math.floor(Date.now() / 30000);
  }
  const key = base32Decode(secret);
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  view.setBigUint64(0, BigInt(counter), false); // big-endian
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const hmac = await crypto.subtle.sign('HMAC', cryptoKey, counterBuf);
  const hmacBytes = new Uint8Array(hmac);
  const offset = hmacBytes[19] & 0x0f;
  const binary = (hmacBytes[offset] & 0x7f) << 24
              | (hmacBytes[offset+1] & 0xff) << 16
              | (hmacBytes[offset+2] & 0xff) << 8
              | (hmacBytes[offset+3] & 0xff);
  const otp = binary % 1000000;
  return String(otp).padStart(6, '0');
}

export async function verifyTOTP(secret, token) {
  const current = await generateTOTP(secret);
  if (current === token) return true;
  // Tolleranza di un passo prima e dopo
  const counter = Math.floor(Date.now() / 30000);
  const prev = await generateTOTP(secret, counter - 1);
  if (prev === token) return true;
  const next = await generateTOTP(secret, counter + 1);
  if (next === token) return true;
  return false;
}

// Helper base32
function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += base32Alphabet[(value >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += base32Alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(str) {
  const bytes = [];
  let bits = 0;
  let value = 0;
  for (let i = 0; i < str.length; i++) {
    const idx = base32Alphabet.indexOf(str[i].toUpperCase());
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}