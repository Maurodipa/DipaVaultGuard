# DipaVaultGuard

Password Manager Personale Zero-Knowledge che funziona interamente nel browser con sincronizzazione cloud tramite Google Drive. Completamente gratuito, open source e serverless.

## 🚀 Caratteristiche Principali
- **Sicurezza Zero-Knowledge (2SKD):** Ispirata all'architettura di 1Password, la crittografia (AES-256-GCM) avviene interamente nel tuo browser locale. Oltre alla password principale, per decifrare il vault su un nuovo dispositivo è richiesta una *Secret Key* locale generata ad alta entropia. Nessun dato non criptato lascia mai il dispositivo.
- **Google Drive Sync Invisibile:** Il vault crittografato viene salvato e sincronizzato automaticamente in tempo reale nella cartella di sistema nascosta (ppDataFolder) del tuo account Google Drive personale. Non "sporca" il tuo Drive!
- **Autenticazione a Due Fattori (2FA):**
  - **Sblocco Biometrico (WebAuthn PRF):** Usa il TouchID/FaceID o Windows Hello del dispositivo per sbloccare l'app rapidamente e in totale sicurezza senza digitare la password.
  - **App Authenticator (TOTP):** Supporto integrato per app come Google Authenticator, Authy, Aegis, ecc.
  - **Codici via Email:** Possibilità di configurare l'invio di OTP via email in assenza di biometria (richiede configurazione EmailJS).
- **Gestione Offline (PWA):** L'app può essere installata su smartphone (iOS/Android) o desktop tramite browser. L'app è strutturata come PWA (Progressive Web App): funziona perfettamente offline (i dati sono salvati localmente) e si auto-sincronizza al ritorno della connessione.
- **Generatore Integrato:** Generatore di password robuste e *passphrase* configurabile.
- **Nessun Server, Nessun Database Backend:** L'infrastruttura si riduce a semplici file statici (HTML/JS/CSS). Può essere ospitata gratuitamente su GitHub Pages.

## 📂 Struttura del Progetto
L'app è costituita interamente da codice front-end vanilla:
- index.html: L'interfaccia utente principale, form, e markup delle schermate (login, dashboard, dettagli).
- js_Claude_2FA/app_Claude_2FA.js: Controller principale dell'applicazione (gestione navigazione schermate, form di login/setup, coordinamento della sincronizzazione automatica).
- js_Claude_2FA/crypto_Claude_2FA.js: Il cuore crittografico basato sull'API Web Crypto nativa. Implementa il sistema 2SKD mescolando password e Secret Key.
- js_Claude_2FA/vault_Claude_2FA.js: Struttura dati del vault (in memoria) e operazioni CRUD (inserimento, cancellazione, aggiornamento, import/export CSV).
- js_Claude_2FA/drive_Claude_2FA.js: Il client Google Drive che sfrutta la libreria ufficiale Google Identity Services (GIS) per la gestione del file cifrato remoto.
- js_Claude_2FA/twofactor_Claude_2FA.js: Logica per il calcolo TOTP, e integrazione con il protocollo di autenticazione FIDO/WebAuthn (con estensione PRF).
- js_Claude_2FA/email-otp_Claude_2FA.js: Logica opzionale per l'invio di codici temporanei OTP via email al momento dell'accesso.
- js_Claude_2FA/password-gen_Claude_2FA.js: Algoritmi locali di generazione di stringhe casuali (password e passphrase).
- js_Claude_2FA/ui_Claude_2FA.js: Interazioni DOM, aggiornamento delle liste (rendering), modal, toggle interattivi e avvisi toast.
- css_Claude_2FA/style_Claude_2FA.css: Tutto lo stile CSS personalizzato per desktop e mobile-first.
- sw_Claude_2FA.js e manifest_Claude_2FA.json: Service Worker e Manifest per il caching offline, l'installazione nativa come PWA.

## 🛠 Come installarlo per un nuovo utente (Guida Passo-Passo)

Vuoi creare la tua copia personale di DipaVaultGuard? È semplicissimo, gratuito a vita e non richiede l'acquisto di server o domini!

### 1. Crea il tuo Repository
Fai il Fork di questo repository, oppure scarica tutti questi file e caricali in un nuovo repository pubblico (o privato) sul tuo account GitHub.

### 2. Attiva GitHub Pages per l'hosting gratuito
Nelle impostazioni (Settings) del tuo repository su GitHub, vai alla sezione **Pages** nel menu laterale. 
Sotto "Build and deployment", come Source scegli "Deploy from a branch", seleziona il branch main e la cartella /(root). Salva.
Dopo un paio di minuti, l'app sarà pubblicata e raggiungibile al tuo URL personale (es. https://il-tuo-nome.github.io/DipaVaultGuard/).

### 3. Configura l'integrazione Google Drive (Client ID)
Affinché l'app possa leggere/scrivere il vault sul *tuo* Google Drive senza alcun backend intermediario, l'app deve essere autorizzata direttamente dal tuo account Google Cloud.
1. Vai su [Google Cloud Console](https://console.cloud.google.com/).
2. Crea un nuovo Progetto (es. "My Password Manager").
3. Dal menu di navigazione, vai su **API e servizi > Libreria** e cerca/abilita la **Google Drive API**.
4. Vai su **API e servizi > Schermata di consenso OAuth**. Configurala come "Esterno", inserisci il nome dell'app, la tua email per supporto e sviluppatore. Nel passaggio "Ambiti" (Scopes) aggiungi lo scope .../auth/drive.appdata (permette all'app di scrivere solo all'interno della sua cartella nascosta dedicata, senza avere accesso agli altri tuoi file su Drive).
5. Vai su **API e servizi > Credenziali**.
6. Clicca su "Crea credenziali" e scegli **ID client OAuth**. Seleziona **Applicazione Web**.
7. In **Origini JavaScript autorizzate** e **URI di reindirizzamento autorizzati**, inserisci l'URL esatto della tua pagina GitHub Pages appena creata (es. https://il-tuo-nome.github.io).
8. Copia il "Client ID" generato (è una lunga stringa che finisce per .apps.googleusercontent.com).

### 4. Primo Avvio e Setup
1. Vai all'URL della tua app pubblicata (su GitHub Pages).
2. Nella schermata di login, tocca l'**icona dell'ingranaggio (Impostazioni)** in alto a destra.
3. Incolla il tuo **Google Client ID** (quello del punto precedente) nel campo dedicato e chiudi le impostazioni.
4. Torna alla schermata principale e scorri in basso fino a **"Sei un nuovo utente?"**.
5. Inserisci una Master Password lunga e sicura e clicca **Crea Vault**.
6. Una volta entrato, vai nelle Impostazioni e clicca su **Attiva protezione 2SKD** (Fortemente consigliato!). L'app ti mostrerà la tua nuova Secret Key: **salvala subito in un posto sicuro**!
7. Infine, tocca l'icona della nuvoletta in alto a destra ("Connetti Google Drive") per salvare questo vault appena creato sul tuo cloud in via definitiva.

### 5. Installa l'App come Nativa
DipaVaultGuard è progettato per sembrare e funzionare come un'app nativa se "installato" sul dispositivo tramite browser.
- **Su Android (Chrome):** Apri l'app nel browser, apri il menu dei 3 puntini e tocca "Aggiungi a schermata Home" o "Installa app".
- **Su iOS (Safari):** Apri l'app, tocca l'icona centrale "Condividi" nella barra inferiore e seleziona "Aggiungi alla schermata Home".
- **Su PC/Mac (Chrome/Edge):** Clicca l'icona dello schermo con la freccetta giù nella barra degli indirizzi in alto.
Una volta installata, potrai sbloccare DipaVaultGuard con il volto/impronta digitale senza dover usare il browser web, anche in assenza di rete internet (Offline mode)!

## 🔐 Sicurezza Avanzata e Dettagli sul 2SKD (Two-Secret Key Derivation)
A differenza dei normali password manager open source base, questa app adotta la protezione Two-Secret Key Derivation (ispirata all'architettura di sicurezza di 1Password).

Il file crittografato che viene inviato ai server di Google non è protetto dalla tua sola password.
La chiave AES-256 finale per decifrare il file non viene derivata solo dalla password, ma da **due segreti incrociati**:
1. **Master Password** (Nota solo al tuo cervello) -> Passata attraverso algoritmo PBKDF2 (600.000 iterazioni)
2. **Secret Key Locale** (Memorizzata nel device e mai inviata in rete) -> Passata per HKDF-SHA256

Le due sequenze crittografiche prodotte subiscono un'operazione crittografica (XOR bit-a-bit).
Se un hacker violasse i server di Google e rubasse fisicamente il tuo file cifrato "DipaVault.bin", e contestualmente indovinasse anche la tua Master Password, **comunque non riuscirebbe ad accedere a nessuna password**, perché per generare la chiave di sblocco mancherebbe la Secret Key locale conservata esclusivamente nel tuo browser!
