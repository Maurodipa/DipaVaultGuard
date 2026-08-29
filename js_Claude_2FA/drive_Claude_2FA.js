export class GoogleDriveClient {
  constructor(clientId) {
    this.clientId = clientId;
    this.tokenClient = null;
    this.accessToken = null;
    this.userInfo = null;
    this.lastSyncTime = null;
    this.initialized = false;
  }

  init() {
    if (!this.clientId) return false;
    try {
      if (typeof google === 'undefined' || !google.accounts || !google.accounts.oauth2) {
        return false;
      }
      this.tokenClient = google.accounts.oauth2.initTokenClient({
        client_id: this.clientId,
        scope: 'https://www.googleapis.com/auth/drive.appdata https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',
        callback: (tokenResponse) => {
          if (tokenResponse && tokenResponse.access_token) {
            this.accessToken = tokenResponse.access_token;
          }
        },
      });
      this.initialized = true;
      return true;
    } catch (e) {
      console.error("Google Identity Services not loaded yet", e);
      return false;
    }
  }

  async authenticate() {
    // Inizializzazione lazy: se non era pronto (caso raro, dato che app.js
    // attende già che Google Identity Services sia caricato prima di questo
    // punto), ci riprova in modo sincrono, SENZA attese asincrone: un
    // eventuale "await" qui spezzerebbe il collegamento diretto con il
    // click dell'utente e farebbe fallire silenziosamente il primo tentativo
    // di autenticazione.
    if (!this.tokenClient) {
      this.init();
    }

    return new Promise((resolve, reject) => {
      if (!this.tokenClient) {
        reject(new Error("Google Identity Services non ancora pronto. Attendi qualche secondo e riprova."));
        return;
      }
      
      this.tokenClient.callback = async (tokenResponse) => {
        if (tokenResponse && tokenResponse.access_token) {
          this.accessToken = tokenResponse.access_token;
          try {
            await this.getUserInfo();
            resolve(this.accessToken);
          } catch (e) {
            reject(e);
          }
        } else {
          reject(new Error("Autenticazione fallita"));
        }
      };
      
      this.tokenClient.requestAccessToken();
    });
  }

  async silentRefresh() {
    return new Promise((resolve, reject) => {
      if (!this.tokenClient) reject(new Error("Client non inizializzato"));
      
      this.tokenClient.callback = (tokenResponse) => {
        if (tokenResponse && tokenResponse.access_token) {
          this.accessToken = tokenResponse.access_token;
          resolve(this.accessToken);
        } else {
          reject(new Error("Refresh fallito"));
        }
      };
      
      this.tokenClient.requestAccessToken({ prompt: '' });
    });
  }

  signOut() {
    if (this.accessToken) {
      google.accounts.oauth2.revoke(this.accessToken, () => {});
    }
    this.accessToken = null;
    this.userInfo = null;
  }

  isAuthenticated() {
    return !!this.accessToken;
  }

  async getUserInfo() {
    if (!this.accessToken) throw new Error("Non autenticato");
    const response = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${this.accessToken}` }
    });
    if (!response.ok) throw new Error("Impossibile recuperare info utente");
    this.userInfo = await response.json();
    return this.userInfo;
  }

  async findVaultFile(fileName = 'dipavault.bin') {
    if (!this.accessToken) throw new Error("Non autenticato");
    
    const query = encodeURIComponent(`name='${fileName}' and 'appDataFolder' in parents and trashed=false`);
    const response = await fetch(`https://www.googleapis.com/drive/v3/files?q=${query}&spaces=appDataFolder&fields=files(id,name,modifiedTime)`, {
      headers: { Authorization: `Bearer ${this.accessToken}` }
    });
    
    if (!response.ok) throw new Error("Errore durante la ricerca del file");
    
    const data = await response.json();
    if (data.files && data.files.length > 0) {
      return data.files[0];
    }
    return null;
  }

  async createVaultFile(data, fileName = 'dipavault.bin') {
    if (!this.accessToken) throw new Error("Non autenticato");
    
    const metadata = {
      name: fileName,
      parents: ['appDataFolder']
    };
    
    const form = new FormData();
    form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
    form.append('file', new Blob([data], { type: 'application/octet-stream' }));
    
    const response = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,modifiedTime', {
      method: 'POST',
      headers: { Authorization: `Bearer ${this.accessToken}` },
      body: form
    });
    
    if (!response.ok) throw new Error("Errore durante la creazione del file");
    this.lastSyncTime = new Date();
    return await response.json();
  }

  async readVaultFile(fileId) {
    if (!this.accessToken) throw new Error("Non autenticato");
    
    const response = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`, {
      headers: { Authorization: `Bearer ${this.accessToken}` }
    });
    
    if (!response.ok) throw new Error("Errore durante la lettura del file");
    
    const buffer = await response.arrayBuffer();
    this.lastSyncTime = new Date();
    return new Uint8Array(buffer);
  }

  async updateVaultFile(fileId, data) {
    if (!this.accessToken) throw new Error("Non autenticato");
    
    const response = await fetch(`https://www.googleapis.com/upload/drive/v3/files/${fileId}?uploadType=media&fields=id,name,modifiedTime`, {
      method: 'PATCH',
      headers: { 
        Authorization: `Bearer ${this.accessToken}`,
        'Content-Type': 'application/octet-stream'
      },
      body: data
    });
    
    if (!response.ok) throw new Error("Errore durante l'aggiornamento del file");
    this.lastSyncTime = new Date();
    return await response.json();
  }

  getLastSyncTime() {
    return this.lastSyncTime;
  }

  // --- File di configurazione OTP via email ---
  // Piccolo file JSON NON cifrato in appDataFolder (separato dal vault vero e proprio), usato
  // per rendere il requisito "serve l'OTP via email" una proprietà del vault stesso, non solo
  // di questo dispositivo. Senza questo, ripristinare il vault su un dispositivo/browser dove
  // non è mai stata configurata la biometria/TOTP/email permetterebbe di entrare con la sola
  // password, perché localmente non ci sarebbe nulla da controllare.
  // Contiene Service ID/Template ID/Public Key di EmailJS e l'email destinatario: valori
  // pensati per essere lato client nel modello di EmailJS (non sono segreti come una password),
  // ma chiunque avesse accesso al tuo Google Drive potrebbe comunque vederli.
  async findOtpConfigFile(fileName = 'dipavault-otp-config.json') {
    if (!this.accessToken) throw new Error("Non autenticato");

    const query = encodeURIComponent(`name='${fileName}' and 'appDataFolder' in parents and trashed=false`);
    const response = await fetch(`https://www.googleapis.com/drive/v3/files?q=${query}&spaces=appDataFolder&fields=files(id,name,modifiedTime)`, {
      headers: { Authorization: `Bearer ${this.accessToken}` }
    });

    if (!response.ok) throw new Error("Errore durante la ricerca della configurazione OTP su Drive");

    const data = await response.json();
    if (data.files && data.files.length > 0) {
      return data.files[0];
    }
    return null;
  }

  async readOtpConfigFile(fileId) {
    if (!this.accessToken) throw new Error("Non autenticato");

    const response = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`, {
      headers: { Authorization: `Bearer ${this.accessToken}` }
    });

    if (!response.ok) throw new Error("Errore durante la lettura della configurazione OTP su Drive");

    return await response.json();
  }

  // Crea o aggiorna il file, a seconda che esista già o meno.
  async saveOtpConfigFile(config, fileName = 'dipavault-otp-config.json') {
    if (!this.accessToken) throw new Error("Non autenticato");

    const existing = await this.findOtpConfigFile(fileName);
    const body = JSON.stringify(config);

    if (existing) {
      const response = await fetch(`https://www.googleapis.com/upload/drive/v3/files/${existing.id}?uploadType=media&fields=id,name,modifiedTime`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${this.accessToken}`, 'Content-Type': 'application/json' },
        body
      });
      if (!response.ok) throw new Error("Errore durante l'aggiornamento della configurazione OTP su Drive");
      return await response.json();
    }

    const metadata = { name: fileName, parents: ['appDataFolder'] };
    const form = new FormData();
    form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
    form.append('file', new Blob([body], { type: 'application/json' }));

    const response = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,modifiedTime', {
      method: 'POST',
      headers: { Authorization: `Bearer ${this.accessToken}` },
      body: form
    });
    if (!response.ok) throw new Error("Errore durante la creazione della configurazione OTP su Drive");
    return await response.json();
  }
}