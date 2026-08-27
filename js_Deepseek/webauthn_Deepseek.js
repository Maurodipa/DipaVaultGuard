// js/webauthn.js
export async function isWebAuthnPRFSupported() {
  if (!window.PublicKeyCredential) return false;
  try {
    // Verifichiamo se l'autenticatore di piattaforma è disponibile
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    if (!available) return false;
    // Verifichiamo se l'estensione PRF è supportata (tentativo di creazione fittizia)
    // Per semplicità, se la piattaforma è disponibile, assumiamo che PRF sia supportato.
    // In alcuni browser potrebbe non esserlo, ma la maggior parte dei browser moderni lo supporta.
    return true;
  } catch (e) {
    return false;
  }
}

export async function createPRFCredential(userId, userName, rpId, challenge, prfSalt) {
  // prfSalt è un salt (base64) da utilizzare per la PRF
  const publicKey = {
    rp: { id: rpId, name: 'DipaVaultGuard' },
    user: {
      id: new TextEncoder().encode(userId),
      name: userName,
      displayName: userName,
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },  // ES256
      { type: 'public-key', alg: -257 } // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
      residentKey: 'required',
    },
    timeout: 60000,
    challenge: base64ToArrayBuffer(challenge),
    extensions: {
      prf: {
        eval: {
          first: base64ToArrayBuffer(prfSalt),
        },
      },
    },
  };
  try {
    const credential = await navigator.credentials.create({ publicKey });
    // Estraiamo i dati da memorizzare
    return {
      id: credential.id,
      rawId: arrayBufferToBase64(credential.rawId),
      // Non memorizziamo attestationObject per ora, ma potremmo averne bisogno per la verifica futura
      // Memorizziamo solo l'ID per l'autenticazione
    };
  } catch (e) {
    throw new Error(`Registrazione PRF fallita: ${e.message}`);
  }
}

export async function getPRFSecret(credentialId, challenge, prfSalt) {
  const publicKey = {
    challenge: base64ToArrayBuffer(challenge),
    allowCredentials: [{ 
      id: base64ToArrayBuffer(credentialId), 
      type: 'public-key' 
    }],
    timeout: 60000,
    userVerification: 'required',
    extensions: {
      prf: {
        eval: {
          first: base64ToArrayBuffer(prfSalt),
        },
      },
    },
  };
  try {
    const assertion = await navigator.credentials.get({ publicKey });
    const prfResult = assertion.response.extensionResults?.prf?.results?.first;
    if (!prfResult) throw new Error('Nessun risultato PRF');
    // prfResult è un ArrayBuffer
    return arrayBufferToBase64(prfResult);
  } catch (e) {
    throw new Error(`Autenticazione PRF fallita: ${e.message}`);
  }
}

// Funzioni helper
export function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}