# DipaVaultGuard

Password Manager Personale Zero-Knowledge che funziona interamente nel browser con sincronizzazione cloud tramite Google Drive e autenticazione a due fattori (biometria/TOTP).

## Caratteristiche

- **Sicurezza Zero-Knowledge:** Tutta la crittografia (AES-256-GCM) avviene nel browser. Nessun dato non criptato lascia mai il dispositivo.
- **Sincronizzazione Cloud:** Salva il tuo vault in un file binario criptato all'interno della cartella nascosta `appDataFolder` del tuo Google Drive.
- **Generatore di password integrato:** Genera password robuste o passphrase (parole separate da trattini) con opzioni personalizzabili.
- **Secondo fattore (2FA):** Supporto per autenticazione biometrica (WebAuthn + PRF) su dispositivi compatibili, con fallback TOTP (Google Authenticator/Authy). La password principale è richiesta obbligatoriamente ogni 7 giorni per motivi di sicurezza.
- **Client-side only:** Nessun server, nessun database backend. Solo file HTML/JS/CSS.
- **PWA (Progressive Web App):** Installabile su smartphone e desktop per un'esperienza nativa e funzionante offline.

## Come iniziare

### 1. Avviare l'app in locale

Poiché utilizza chiamate ES Modules e l'API Web Crypto, è necessario servire i file da un server HTTP locale (non tramite il protocollo `file://`).

Se hai Python installato:
```bash
python -m http.server 8000
Quindi apri il browser a: http://localhost:8000

2. Configurare l'integrazione Google Drive (Opzionale)
Per poter sincronizzare i dati su Google Drive, devi creare un progetto Google Cloud e generare un Client ID.

Vai su Google Cloud Console

Crea un nuovo progetto

Vai su API e servizi > Libreria e abilita la Google Drive API

Vai su API e servizi > Schermata di consenso OAuth, configurala come "Esterno" e aggiungi lo scope .../auth/drive.appdata

Vai su API e servizi > Credenziali

Crea credenziali di tipo ID client OAuth per applicazione Web

Aggiungi il tuo dominio (es. http://localhost:8000 o l'URL di produzione) sia in Origini JavaScript autorizzate che in URI di reindirizzamento autorizzati

Copia il Client ID generato, apri l'app DipaVaultGuard, vai nelle "Impostazioni" e incollalo nel campo apposito.

Struttura del Progetto
text
/
├── index.html
├── manifest.json
├── sw.js
├── icons/
│   ├── icon-192.png
│   └── icon-512.png
├── css/
│   └── style.css
└── js/
    ├── app.js              # Logica principale e gestione eventi
    ├── ui.js               # Interfaccia utente e rendering
    ├── crypto.js           # Motore crittografico (Web Crypto API)
    ├── vault.js            # Gestione dati e serializzazione vault
    ├── drive.js            # Integrazione client Google Drive (GIS)
    ├── password-gen.js     # Generatore di password e passphrase
    ├── webauthn.js         # Autenticazione biometrica WebAuthn + PRF
    └── totp.js             # Implementazione TOTP (RFC 6238)
Descrizione dei file principali
/js/crypto.js: Motore crittografico usando l'API Web Crypto. Implementa packVault e unpackVault per cifrare/decifrare il vault con AES-256-GCM, e deriveVaultKeyWithSecondFactor per combinare password e secondo fattore.

/js/vault.js: Gestione dei dati del vault (items, categorie, metadati 2FA). Gestisce la creazione, lo sblocco, il blocco e le operazioni CRUD.

/js/drive.js: Integrazione client per Google Drive utilizzando Google Identity Services (GIS). Gestisce autenticazione OAuth, caricamento e download del vault criptato.

/js/ui.js e /js/app.js: Logica dell'interfaccia utente e coordinamento generale dell'applicazione.

/js/password-gen.js: Motore di generazione delle password con opzioni (lunghezza, caratteri, esclusione ambigui) e passphrase con wordlist italiana.

/js/webauthn.js: Gestione autenticazione biometrica WebAuthn + PRF (secondo fattore crittografico). Include funzioni per verificare il supporto, registrare la credenziale e ottenere il segreto PRF.

/js/totp.js: Implementazione TOTP (RFC 6238) con HMAC-SHA1, base32 e generazione/verifica codici a 6 cifre con tolleranza di ±1 intervallo.

/sw.js e /manifest.json: Configurazione della PWA per l'uso offline e l'installazione.

Sicurezza
DipaVaultGuard usa PBKDF2-HMAC-SHA256 con 600.000 iterazioni (lo stesso standard di Bitwarden) per derivare una master key. La master key cripta una chiave di vault casuale (Symmetric Vault Key), che a sua volta cripta l'intero file JSON del vault in modalità AES-256-GCM con IV casuale per ogni cifratura.

Secondo fattore (2FA) - WebAuthn PRF
Sui dispositivi che supportano WebAuthn + PRF (estensione per la derivazione di chiavi), il secondo fattore biometrico (impronta/volto) viene utilizzato per proteggere crittograficamente la chiave di vault. Durante la configurazione:

Viene generato un biometricSalt casuale memorizzato nel vault.

La credenziale WebAuthn viene registrata con l'estensione PRF, usando il salt come input per derivare un segreto.

Durante il login, il segreto PRF viene ottenuto tramite autenticazione biometrica.

Il segreto PRF viene combinato con la password per derivare la chiave finale (tramite deriveVaultKeyWithSecondFactor).

Il segreto PRF non viene mai memorizzato sul dispositivo né nel vault, rendendo impossibile l'accesso senza il dispositivo biometrico e l'autenticazione dell'utente.

Fallback TOTP
Per dispositivi che non supportano PRF, l'app offre un fallback TOTP (RFC 6238) con le seguenti caratteristiche:

Generazione di un segreto casuale di 16 byte codificato in base32.

Supporto per la scansione tramite QR code (Google Authenticator, Authy, ecc.).

Verifica del codice con tolleranza di ±1 intervallo (30 secondi) per compensare lievi differenze di orario.

Il segreto TOTP viene memorizzato nel vault (protetto dalla password) e viene utilizzato sia per la verifica che per la derivazione della chiave.

Scadenza password (7 giorni)
Per motivi di sicurezza, ogni 7 giorni viene richiesta obbligatoriamente la password principale completa, indipendentemente dal secondo fattore utilizzato nel frattempo. Questo meccanismo:

Previene accessi indesiderati in caso di furto del dispositivo biometrico.

Assicura che l'utente ricordi la password principale.

Riduce il rischio di utilizzo prolungato senza reinserimento della password.

Il timestamp dell'ultimo inserimento della password completa (lastFullPasswordCheck) viene memorizzato nel vault e verificato ad ogni accesso.

Tecnologie utilizzate
Web Crypto API per tutte le operazioni crittografiche (AES-GCM, PBKDF2, HMAC).

WebAuthn + PRF per l'autenticazione biometrica crittografica.

Google Identity Services (GIS) per l'autenticazione OAuth con Google Drive.

Google Drive API v3 per la sincronizzazione del vault cifrato.

QRCode.js per la generazione dei QR code TOTP.

Service Worker per il funzionamento offline e la PWA.

Licenza
Questo progetto è rilasciato sotto licenza MIT.