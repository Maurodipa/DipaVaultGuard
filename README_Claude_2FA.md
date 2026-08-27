# DipaVaultGuard

Password Manager Personale Zero-Knowledge che funziona interamente nel browser con sincronizzazione cloud tramite Google Drive.

## Caratteristiche
- **Sicurezza Zero-Knowledge:** Tutta la crittografia (AES-256-GCM) avviene nel browser. Nessun dato non criptato lascia mai il dispositivo.
- **Autenticazione a due fattori:** oltre alla password principale, è possibile richiedere impronta/volto (WebAuthn + PRF) o un codice TOTP da app authenticator per aprire il vault. Ogni 7 giorni viene comunque richiesta la password completa.
- **Sincronizzazione Cloud:** Salva il tuo vault in un file binario criptato all'interno della cartella nascosta `appDataFolder` del tuo Google Drive.
- **Generatore di password integrato:** Genera password robuste o passphrase (parole separate da trattini).
- **Client-side only:** Nessun server, nessun database backend. Solo file HTML/JS/CSS.
- **PWA (Progressive Web App):** Installabile su smartphone e desktop per un'esperienza nativa e funzionante offline.

## Come iniziare

### 1. Avviare l'app in locale
Poiché utilizza chiamate ES Modules e l'API Web Crypto, è necessario servire i file da un server HTTP locale (non tramite il protocollo `file://`).

Se hai Python installato:
```bash
python -m http.server 8000
```
Quindi apri il browser a: `http://localhost:8000`

### 2. Configurare l'integrazione Google Drive (Opzionale)
Per poter sincronizzare i dati su Google Drive, devi creare un progetto Google Cloud e generare un Client ID.
1. Vai su [Google Cloud Console](https://console.cloud.google.com/)
2. Crea un nuovo progetto
3. Vai su **API e servizi > Libreria** e abilita la **Google Drive API**
4. Vai su **API e servizi > Schermata di consenso OAuth**, configurala come "Esterno" e aggiungi lo scope `.../auth/drive.appdata`
5. Vai su **API e servizi > Credenziali**
6. Crea credenziali di tipo **ID client OAuth per applicazione Web**
7. Aggiungi il tuo dominio (es. `http://localhost:8000` o l'URL di produzione) sia in **Origini JavaScript autorizzate** che in **URI di reindirizzamento autorizzati**
8. Copia il Client ID generato, apri l'app DipaVaultGuard, vai nelle "Impostazioni" e incollalo nel campo apposito.

## Struttura del Progetto

- `/js/crypto.js`: Motore crittografico usando l'API Web Crypto.
- `/js/vault.js`: Gestione dei dati e serializzazione in formato binario.
- `/js/twofactor.js`: Autenticazione a due fattori (biometria WebAuthn/PRF e TOTP).
- `/js/drive.js`: Integrazione client per Google Drive (GIS).
- `/js/ui.js` e `/js/app.js`: Logica dell'interfaccia utente.
- `/js/password-gen.js`: Motore di generazione delle password.
- `/sw.js` e `/manifest.json`: Configurazione della PWA per l'uso offline e l'installazione.

## Sicurezza

DipaVaultGuard usa **PBKDF2-HMAC-SHA256 con 600.000 iterazioni** (lo stesso standard di Bitwarden) per derivare una master key. La master key cripta una chiave di volta casuale (Symmetric Vault Key), che a sua volta cripta l'intero file JSON del vault in modalità **AES-256-GCM**.

### Autenticazione a due fattori

Attivabile dalle Impostazioni una volta sbloccato il vault:

- **Sblocco biometrico** (consigliato): usa l'estensione **PRF** di WebAuthn. Il segreto vive nell'hardware sicuro del dispositivo (es. Secure Enclave/StrongBox) e non è mai estraibile da JavaScript — solo il suo output, e solo dopo una verifica biometrica riuscita. Una copia della Vault Key viene cifrata con una chiave derivata (HKDF-SHA256) da questo output, e salvata solo su questo dispositivo.
- **Codice TOTP** (fallback per dispositivi senza supporto PRF, es. alcuni desktop): compatibile con qualsiasi app authenticator standard (Google Authenticator, Authy, Aegis...). Nota: a differenza della biometria, il segreto TOTP deve essere presente anche in questo browser per poter verificare i codici — è quindi una protezione più debole in caso di estrazione diretta dei dati del browser, ma resta un secondo fattore reale contro l'accesso casuale a un dispositivo sbloccato.
- Indipendentemente dal metodo usato, **ogni 7 giorni viene comunque richiesta la password principale completa**.
- Il file sincronizzato su Google Drive resta protetto **solo** dalla password principale: il ripristino su un nuovo dispositivo richiede sempre la password (le registrazioni biometriche/TOTP sono legate al singolo dispositivo).
