// We will build ui.js to export everything needed.
// First let's define the STRINGS exactly as requested.
const STRINGS = {
  appName: 'DipaVaultGuard',
  tagline: 'Password Manager Sicuro',
  createVault: 'Crea il tuo vault sicuro',
  masterPassword: 'Password principale',
  confirmPassword: 'Conferma password',
  unlock: 'Sblocca',
  lock: 'Blocca',
  create: 'Crea Vault',
  search: 'Cerca...',
  allItems: 'Tutte le voci',
  favorites: 'Preferiti',
  addCategory: '+ Aggiungi categoria',
  newItem: 'Nuova Voce',
  editItem: 'Modifica Voce',
  save: 'Salva',
  cancel: 'Annulla',
  delete: 'Elimina',
  edit: 'Modifica',
  copy: 'Copia',
  copied: 'Copiato!',
  generate: 'Genera',
  regenerate: 'Rigenera',
  usePassword: 'Usa questa password',
  name: 'Nome',
  url: 'Sito web',
  username: 'Nome utente',
  password: 'Password',
  notes: 'Note',
  category: 'Categoria',
  favorite: 'Preferito',
  settings: 'Impostazioni',
  security: 'Sicurezza',
  data: 'Dati',
  info: 'Informazioni',
  googleDrive: 'Google Drive',
  connect: 'Connetti',
  disconnect: 'Disconnetti',
  syncNow: 'Sincronizza ora',
  lastSync: 'Ultima sincronizzazione',
  connected: 'Connesso',
  disconnected: 'Disconnesso',
  changePassword: 'Cambia password principale',
  currentPassword: 'Password attuale',
  newPassword: 'Nuova password',
  confirmNewPassword: 'Conferma nuova password',
  autoLock: 'Blocco automatico',
  autoLockOptions: { 1: '1 minuto', 5: '5 minuti', 15: '15 minuti', 30: '30 minuti', 0: 'Mai' },
  exportCSV: 'Esporta CSV',
  importCSV: 'Importa CSV',
  exportWarning: 'Attenzione: il file esportato NON sarà criptato!',
  importSuccess: (n) => `${n} voci importate con successo!`,
  noItems: 'Nessuna voce trovata',
  noItemsHint: 'Clicca + per aggiungere la tua prima credenziale',
  passwordLength: 'Lunghezza',
  uppercase: 'Maiuscole (A-Z)',
  lowercase: 'Minuscole (a-z)',
  numbers: 'Numeri (0-9)',
  symbols: 'Simboli (!@#$...)',
  excludeAmbiguous: 'Escludi caratteri ambigui',
  passphrase: 'Passphrase',
  wordCount: 'Numero parole',
  separator: 'Separatore',
  passwordStrength: 'Sicurezza password',
  deleteConfirm: 'Sei sicuro di voler eliminare questa voce?',
  deleteConfirmTitle: 'Conferma eliminazione',
  wrongPassword: 'Password principale errata',
  passwordMismatch: 'Le password non coincidono',
  passwordTooShort: 'La password deve essere di almeno 8 caratteri',
  vaultCreated: 'Vault creato con successo!',
  vaultUnlocked: 'Vault sbloccato',
  vaultLocked: 'Vault bloccato',
  itemSaved: 'Voce salvata',
  itemDeleted: 'Voce eliminata',
  passwordCopied: 'Password copiata (cancellata tra 30s)',
  usernameCopied: 'Nome utente copiato',
  syncSuccess: 'Sincronizzazione completata',
  syncError: 'Errore di sincronizzazione',
  passwordChanged: 'Password principale cambiata con successo',
  driveConnected: 'Google Drive connesso',
  driveDisconnected: 'Google Drive disconnesso',
  localVaultFound: 'Vault locale trovato',
  driveVaultFound: 'Vault trovato su Google Drive',
  createNew: 'Crea nuovo vault',
  encryptionInfo: 'AES-256-GCM + PBKDF2 (600.000 iterazioni)',
  version: 'Versione 1.0.0'
};

import { generatePassword, generatePassphrase, calculateStrength } from './password-gen_Claude_2FA.js';
import { isBiometricRegistered, isTOTPRegistered } from './twofactor_Claude_2FA.js';
import { isEmailOtpConfigured, getConfig as getEmailOtpConfig } from './email-otp_Claude_2FA.js';

let appVault = null;
let appDriveClient = null;
let currentFilter = 'all';
let autoLockTimerId = null;

export function initUI(vault, driveClient) {
  appVault = vault;
  appDriveClient = driveClient;

  // Global event delegation
  document.body.addEventListener('click', (e) => {
    resetAutoLockTimer();
    
    // Toggle password visibility
    const toggleBtn = e.target.closest('.btn-toggle-visibility, .toggle-password');
    if (toggleBtn) {
      const targetId = toggleBtn.getAttribute('data-target');
      const targetEl = document.getElementById(targetId);
      if (targetEl) {
        if (targetEl.tagName === 'INPUT') {
          const isPassword = targetEl.type === 'password';
          targetEl.type = isPassword ? 'text' : 'password';
          toggleBtn.innerHTML = `<svg class="icon"><use href="#icon-${isPassword ? 'eye-slash' : 'eye'}"></use></svg>`;
        } else {
          // For span elements
          const isHidden = targetEl.classList.contains('obfuscated');
          if (isHidden) {
            targetEl.classList.remove('obfuscated');
            targetEl.textContent = document.getElementById(targetId + '-raw').value;
            toggleBtn.innerHTML = `<svg class="icon"><use href="#icon-eye-slash"></use></svg>`;
          } else {
            targetEl.classList.add('obfuscated');
            targetEl.textContent = '••••••••••••';
            toggleBtn.innerHTML = `<svg class="icon"><use href="#icon-eye"></use></svg>`;
          }
        }
      }
    }

    // Close modals
    if (e.target.closest('.btn-close-modal') || e.target.classList.contains('modal-backdrop')) {
      const modal = e.target.closest('.modal');
      if (modal) modal.classList.add('hidden');
    }
    
    // Close generator modal specifically
    if (e.target.closest('.btn-close-modal-generator') || (e.target.classList.contains('modal-backdrop') && e.target.closest('#modal-password-generator'))) {
      document.getElementById('modal-password-generator').classList.add('hidden');
    }

    // Sidebar navigation
    const navItem = e.target.closest('.nav-item');
    if (navItem) {
      document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
      navItem.classList.add('active');
      const filter = navItem.getAttribute('data-filter');
      currentFilter = filter;
      document.getElementById('sidebar').classList.remove('mobile-open');
      document.getElementById('list-title').textContent = navItem.textContent.trim().split('\n')[0];
      document.getElementById('list-header').classList.remove('hidden');
      renderItemList(appVault.getAllItems());
    }

    // Mobile menu toggle
    if (e.target.closest('#btn-mobile-menu')) {
      document.getElementById('sidebar').classList.add('mobile-open');
    }
    if (e.target.id === 'sidebar-backdrop') {
      document.getElementById('sidebar').classList.remove('mobile-open');
    }

    // FAB add
    if (e.target.closest('#btn-fab-add')) {
      openItemEdit(null);
    }

    // Copy functionality
    const copyBtn = e.target.closest('.btn-copy');
    if (copyBtn) {
      const targetId = copyBtn.getAttribute('data-copy-target');
      const targetEl = document.getElementById(targetId);
      let textToCopy = '';
      if (targetEl.tagName === 'INPUT') {
        textToCopy = targetEl.value;
      } else {
        textToCopy = targetEl.textContent;
      }
      
      if (textToCopy) {
        navigator.clipboard.writeText(textToCopy).then(() => {
          showToast(targetId.includes('password') ? STRINGS.passwordCopied : STRINGS.copied, 'success');
          // Auto-clear clipboard after 30s
          setTimeout(() => {
            navigator.clipboard.writeText('');
          }, 30000);
        });
      }
    }
  });

  // Search input with debounce
  let searchTimeout;
  document.getElementById('search-input').addEventListener('input', (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      const query = e.target.value.trim();
      if (query) {
        const results = appVault.searchItems(query);
        renderItemList(results);
        document.getElementById('list-title').textContent = `Risultati per "${query}"`;
      } else {
        renderItemList(appVault.getAllItems());
        document.getElementById('list-title').textContent = STRINGS.allItems;
      }
    }, 200);
  });

  // Password Generator Events
  document.getElementById('btn-open-generator').addEventListener('click', () => {
    openPasswordGenerator((newPassword) => {
      document.getElementById('edit-item-password').value = newPassword;
      document.getElementById('edit-item-password').dispatchEvent(new Event('input'));
    });
  });
  
  const updateGen = () => {
    const isPassphrase = document.getElementById('gen-tab-passphrase').classList.contains('active');
    let pwd = '';
    if (isPassphrase) {
      pwd = generatePassphrase({
        wordCount: parseInt(document.getElementById('gen-words').value),
        separator: document.getElementById('gen-separator').value
      });
    } else {
      pwd = generatePassword({
        length: parseInt(document.getElementById('gen-length').value),
        uppercase: document.getElementById('gen-opt-upper').checked,
        lowercase: document.getElementById('gen-opt-lower').checked,
        numbers: document.getElementById('gen-opt-nums').checked,
        symbols: document.getElementById('gen-opt-syms').checked,
        excludeAmbiguous: document.getElementById('gen-opt-ambig').checked
      });
    }
    document.getElementById('generated-password-display').textContent = pwd;
  };

  document.getElementById('btn-gen-refresh').addEventListener('click', updateGen);
  
  ['gen-length', 'gen-words'].forEach(id => {
    document.getElementById(id).addEventListener('input', (e) => {
      document.getElementById(id === 'gen-length' ? 'gen-len-val' : 'gen-words-val').textContent = e.target.value;
      updateGen();
    });
  });

  ['gen-opt-upper', 'gen-opt-lower', 'gen-opt-nums', 'gen-opt-syms', 'gen-opt-ambig', 'gen-separator'].forEach(id => {
    document.getElementById(id).addEventListener('change', updateGen);
  });

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
      btn.classList.add('active');
      document.getElementById(btn.getAttribute('data-tab')).classList.remove('hidden');
      updateGen();
    });
  });

  document.getElementById('btn-use-generated').addEventListener('click', () => {
    const pwd = document.getElementById('generated-password-display').textContent;
    if (window.passwordGeneratorCallback) {
      window.passwordGeneratorCallback(pwd);
    }
    document.getElementById('modal-password-generator').classList.add('hidden');
  });

  document.getElementById('btn-gen-copy').addEventListener('click', () => {
    const pwd = document.getElementById('generated-password-display').textContent;
    navigator.clipboard.writeText(pwd).then(() => showToast(STRINGS.copied, 'success'));
  });

  // Password strength indicators
  ['setup-password', 'edit-item-password'].forEach(id => {
    const input = document.getElementById(id);
    if (!input) return;
    input.addEventListener('input', (e) => {
      const pfx = id === 'setup-password' ? 'setup' : 'edit';
      const strength = calculateStrength(e.target.value);
      const bar = document.getElementById(`${pfx}-strength-fill`);
      const lbl = document.getElementById(`${pfx}-strength-label`);
      if (e.target.value) {
        bar.style.width = `${strength.score * 20}%`;
        bar.style.backgroundColor = strength.color;
        if(lbl) lbl.textContent = strength.label;
      } else {
        bar.style.width = '0%';
        if(lbl) lbl.textContent = '';
      }
    });
  });

  // Keybindings
  document.addEventListener('keydown', (e) => {
    resetAutoLockTimer();
    if (e.ctrlKey && e.key === 'f') {
      e.preventDefault();
      document.getElementById('search-input').focus();
    }
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal').forEach(m => m.classList.add('hidden'));
    }
  });
  
  // Settings - Add Category
  document.getElementById('btn-add-category').addEventListener('click', () => {
    const name = prompt("Nome nuova categoria:");
    if (name && name.trim()) {
      appVault.addCategory(name.trim());
      renderCategories(appVault.getCategories(), currentFilter);
      // We should trigger a save here, handled by app.js usually, but let's dispatch an event
      document.dispatchEvent(new CustomEvent('vault-updated'));
    }
  });

  // Settings modals
  document.getElementById('btn-settings').addEventListener('click', openSettings);
  
  document.getElementById('settings-autolock').addEventListener('change', (e) => {
    const mins = parseInt(e.target.value);
    const settings = JSON.parse(localStorage.getItem('dipavaultguard_settings') || '{}');
    settings.autoLockMinutes = mins;
    localStorage.setItem('dipavaultguard_settings', JSON.stringify(settings));
    startAutoLockTimer(mins);
  });
  
  document.getElementById('settings-google-client-id').addEventListener('change', (e) => {
    const settings = JSON.parse(localStorage.getItem('dipavaultguard_settings') || '{}');
    settings.googleClientId = e.target.value.trim();
    localStorage.setItem('dipavaultguard_settings', JSON.stringify(settings));
  });

  document.getElementById('btn-export-csv').addEventListener('click', () => {
    const csv = appVault.exportToCSV();
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dipavault_export_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  });

  document.getElementById('btn-import-csv-trigger').addEventListener('click', () => {
    document.getElementById('file-import-csv').click();
  });

  document.getElementById('file-import-csv').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (ev) => {
        const count = appVault.importFromCSV(ev.target.result);
        showToast(STRINGS.importSuccess(count), 'success');
        renderItemList(appVault.getAllItems());
        document.dispatchEvent(new CustomEvent('vault-updated'));
      };
      reader.readAsText(file);
    }
  });

  // Register activity listeners
  ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'].forEach(evt => {
    document.addEventListener(evt, resetAutoLockTimer, { passive: true });
  });
}

export function showScreen(screenId) {
  document.querySelectorAll('.screen').forEach(s => s.classList.add('hidden'));
  const screen = document.getElementById(screenId);
  if (screen) screen.classList.remove('hidden');
}

export function showToast(message, type = 'info', durationMs = null) {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${message}</span>`;
  container.appendChild(toast);

  // Trigger animation
  setTimeout(() => toast.classList.add('show'), 10);

  // I messaggi di errore restano visibili più a lungo (6s) di quelli di successo/info (3s):
  // sono spesso più lunghi e più importanti da leggere con calma, specialmente su mobile.
  const effectiveDuration = durationMs !== null ? durationMs : (type === 'error' ? 6000 : 3000);

  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, effectiveDuration);
}


function getFaviconUrl(urlStr) {
  try {
    const url = new URL(urlStr);
    return `https://www.google.com/s2/favicons?domain=${url.hostname}&sz=32`;
  } catch (e) {
    return '';
  }
}

export function renderItemList(items) {
  const container = document.getElementById('items-container');
  const emptyState = document.getElementById('empty-state');
  
  // Apply filters
  let filteredItems = items;
  if (currentFilter === 'favorites') {
    filteredItems = items.filter(i => i.favorite);
  } else if (currentFilter !== 'all') {
    filteredItems = items.filter(i => i.category === currentFilter);
  }

  container.innerHTML = '';
  
  if (filteredItems.length === 0) {
    emptyState.classList.remove('hidden');
  } else {
    emptyState.classList.add('hidden');
    
    filteredItems.forEach(item => {
      const card = document.createElement('div');
      card.className = 'item-card';
      
      const iconUrl = item.url ? getFaviconUrl(item.url) : '';
      const initial = item.name.charAt(0).toUpperCase();
      
      card.innerHTML = `
        ${iconUrl 
          ? `<img src="${iconUrl}" class="item-icon" alt="${item.name}" onerror="this.style.display='none';this.nextElementSibling.style.display='flex';">
             <div class="item-avatar" style="display:none;">${initial}</div>`
          : `<div class="item-avatar">${initial}</div>`
        }
        <div class="item-details">
            <div class="item-name">${item.name} ${item.favorite ? '<svg class="icon text-warning" style="width:14px;height:14px;"><use href="#icon-star"></use></svg>' : ''}</div>
            <div class="item-sub">${item.username || ''} ${item.url ? ` • ${(() => { try { return new URL(item.url.startsWith('http') ? item.url : 'https://' + item.url).hostname; } catch(e) { return item.url; } })()}` : ''}</div>
        </div>
        <div class="item-actions">
          <button class="btn-icon btn-sm btn-copy-pwd" title="Copia Password" data-pwd="${item.password || ''}"><svg class="icon"><use href="#icon-copy"></use></svg></button>
        </div>
      `;
      
      card.addEventListener('click', (e) => {
        if (!e.target.closest('.item-actions')) {
          openItemView(item);
        }
      });
      
      const copyBtn = card.querySelector('.btn-copy-pwd');
      copyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const pwd = copyBtn.getAttribute('data-pwd');
        if (pwd) {
          navigator.clipboard.writeText(pwd).then(() => {
            showToast(STRINGS.passwordCopied, 'success');
            setTimeout(() => navigator.clipboard.writeText(''), 30000);
          });
        }
      });
      
      container.appendChild(card);
    });
  }

  // Update counts
  document.getElementById('badge-all').textContent = appVault.getAllItems().length;
  document.getElementById('badge-favorites').textContent = appVault.getAllItems().filter(i => i.favorite).length;
}

export function renderCategories(categories, activeCategory) {
  const list = document.getElementById('category-list');
  list.innerHTML = '';
  
  categories.forEach(cat => {
    const li = document.createElement('li');
    const itemsInCat = appVault.getItemsByCategory(cat).length;
    li.innerHTML = `
      <button class="nav-item ${activeCategory === cat ? 'active' : ''}" data-filter="${cat}">
        <svg class="icon text-muted"><use href="#icon-shield"></use></svg>
        <span>${cat}</span>
        <span class="badge">${itemsInCat}</span>
      </button>
    `;
    list.appendChild(li);
  });
}

export function openItemView(item) {
  const modal = document.getElementById('modal-item-view');
  
  document.getElementById('view-item-name').textContent = item.name;
  
  const urlEl = document.getElementById('view-item-url');
  if (item.url) {
    urlEl.href = item.url;
    urlEl.textContent = item.url;
    urlEl.parentElement.classList.remove('hidden');
  } else {
    urlEl.parentElement.classList.add('hidden');
  }

  document.getElementById('view-item-username').textContent = item.username || '-';
  
  const pwdEl = document.getElementById('view-item-password');
  const pwdRawEl = document.getElementById('view-item-password-raw');
  pwdRawEl.value = item.password || '';
  pwdEl.textContent = '••••••••••••';
  pwdEl.classList.add('obfuscated');
  
  const notesEl = document.getElementById('view-item-notes');
  if (item.notes) {
    notesEl.textContent = item.notes;
    document.getElementById('view-item-notes-group').classList.remove('hidden');
  } else {
    document.getElementById('view-item-notes-group').classList.add('hidden');
  }
  
  const catEl = document.getElementById('view-item-category');
  if (item.category) {
    catEl.textContent = item.category;
    catEl.classList.remove('hidden');
  } else {
    catEl.classList.add('hidden');
  }
  
  const dateStr = new Date(item.updatedAt || item.createdAt).toLocaleDateString('it-IT', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute:'2-digit' });
  document.getElementById('view-item-date').textContent = `Aggiornato il ${dateStr}`;

  // Icon
  const iconImg = document.getElementById('view-item-icon');
  const avatarDiv = document.getElementById('view-item-avatar');
  if (item.url) {
    iconImg.src = getFaviconUrl(item.url);
    iconImg.style.display = 'block';
    avatarDiv.style.display = 'none';
  } else {
    iconImg.style.display = 'none';
    avatarDiv.textContent = item.name.charAt(0).toUpperCase();
    avatarDiv.style.display = 'flex';
  }

  // Bind actions
  const editBtn = document.getElementById('btn-view-edit');
  const delBtn = document.getElementById('btn-view-delete');
  
  editBtn.onclick = () => {
    modal.classList.add('hidden');
    openItemEdit(item);
  };
  
  delBtn.onclick = () => {
    if (confirm(STRINGS.deleteConfirm)) {
      appVault.deleteItem(item.id);
      modal.classList.add('hidden');
      renderItemList(appVault.getAllItems());
      renderCategories(appVault.getCategories(), currentFilter);
      showToast(STRINGS.itemDeleted, 'success');
      document.dispatchEvent(new CustomEvent('vault-updated'));
    }
  };
  
  // Reset visibility toggle button icon
  const toggleBtn = modal.querySelector('.btn-toggle-visibility');
  if(toggleBtn) toggleBtn.innerHTML = `<svg class="icon"><use href="#icon-eye"></use></svg>`;

  modal.classList.remove('hidden');
}

export function openItemEdit(item = null) {
  const modal = document.getElementById('modal-item-edit');
  const form = document.getElementById('form-item-edit');
  form.reset();
  
  document.getElementById('edit-item-title').textContent = item ? STRINGS.editItem : STRINGS.newItem;
  
  // Populate categories
  const catSelect = document.getElementById('edit-item-category');
  catSelect.innerHTML = '<option value="">Nessuna categoria</option>';
  appVault.getCategories().forEach(cat => {
    catSelect.innerHTML += `<option value="${cat}">${cat}</option>`;
  });
  
  if (item) {
    document.getElementById('edit-item-id').value = item.id;
    document.getElementById('edit-item-name').value = item.name || '';
    document.getElementById('edit-item-url').value = item.url || '';
    document.getElementById('edit-item-username').value = item.username || '';
    document.getElementById('edit-item-password').value = item.password || '';
    document.getElementById('edit-item-notes').value = item.notes || '';
    document.getElementById('edit-item-category').value = item.category || '';
    document.getElementById('edit-item-favorite').checked = !!item.favorite;
    document.getElementById('edit-item-password').dispatchEvent(new Event('input')); // trigger strength
  } else {
    document.getElementById('edit-item-id').value = '';
    document.getElementById('edit-strength-fill').style.width = '0%';
    document.getElementById('edit-strength-label').textContent = '';
  }
  
  // Reset password visibility
  document.getElementById('edit-item-password').type = 'password';
  const toggleBtn = form.querySelector('.toggle-password');
  if(toggleBtn) toggleBtn.innerHTML = `<svg class="icon"><use href="#icon-eye"></use></svg>`;

  modal.classList.remove('hidden');
}

export function openPasswordGenerator(callback = null) {
  window.passwordGeneratorCallback = callback;
  const modal = document.getElementById('modal-password-generator');
  document.getElementById('btn-gen-refresh').click(); // generate initial
  modal.classList.remove('hidden');
}

export function openSettings() {
  const modal = document.getElementById('modal-settings');
  
  const settings = JSON.parse(localStorage.getItem('dipavaultguard_settings') || '{}');
  document.getElementById('settings-autolock').value = settings.autoLockMinutes || 5;
  document.getElementById('settings-google-client-id').value = settings.googleClientId || '';
  
  if (appDriveClient && appDriveClient.isAuthenticated()) {
    document.getElementById('settings-drive-status').textContent = `${STRINGS.connected} (${appDriveClient.userInfo?.email || ''})`;
    document.getElementById('btn-settings-drive-toggle').textContent = STRINGS.disconnect;
    document.querySelectorAll('.drive-connected-only').forEach(el => el.classList.remove('hidden'));
    
    const lastSync = appDriveClient.getLastSyncTime();
    document.getElementById('settings-drive-last-sync').textContent = lastSync ? lastSync.toLocaleString('it-IT') : 'Mai';
  } else {
    document.getElementById('settings-drive-status').textContent = STRINGS.disconnected;
    document.getElementById('btn-settings-drive-toggle').textContent = STRINGS.connect;
    document.querySelectorAll('.drive-connected-only').forEach(el => el.classList.add('hidden'));
  }

  updateSecuritySettingsUI({
    biometricEnabled: isBiometricRegistered(),
    totpEnabled: isTOTPRegistered()
  });
  updateEmailOtpSettingsUI();

  const twoSkdStatus = document.getElementById('settings-2skd-status');
  const btnEnable2SKDEl = document.getElementById('btn-enable-2skd');
  const twoSkdActive = appVault && typeof appVault.isTwoSecretKeyDerivationEnabled === 'function' && appVault.isTwoSecretKeyDerivationEnabled();
  if (twoSkdStatus) twoSkdStatus.textContent = twoSkdActive ? 'Attiva' : 'Non attiva';
  if (btnEnable2SKDEl) btnEnable2SKDEl.disabled = !!twoSkdActive;

  modal.classList.remove('hidden');
}

// Aggiorna la sezione "Verifica via email (OTP)" nelle impostazioni: stato + precompila i
// campi con la configurazione già salvata (se presente), così l'utente non deve reinserirla
// ogni volta che apre le impostazioni.
export function updateEmailOtpSettingsUI() {
  const statusEl = document.getElementById('settings-email-otp-status');
  const configured = isEmailOtpConfigured();
  if (statusEl) {
    statusEl.textContent = configured ? 'Configurato' : 'Non configurato';
  }

  const cfg = getEmailOtpConfig();
  const recipientEl = document.getElementById('email-otp-recipient');
  const serviceEl = document.getElementById('email-otp-service-id');
  const templateEl = document.getElementById('email-otp-template-id');
  const publicKeyEl = document.getElementById('email-otp-public-key');
  if (cfg && recipientEl && serviceEl && templateEl && publicKeyEl) {
    recipientEl.value = cfg.recipientEmail || '';
    serviceEl.value = cfg.serviceId || '';
    templateEl.value = cfg.templateId || '';
    publicKeyEl.value = cfg.publicKey || '';
  }
}

// Aggiorna la sezione "Autenticazione a due fattori" nelle impostazioni in base allo stato
// attuale (registrato/non registrato). Chiamata da app.js, che conosce lo stato tramite
// twofactor.js.
export function updateSecuritySettingsUI({ biometricEnabled, totpEnabled }) {
  const bioStatus = document.getElementById('settings-biometric-status');
  const bioEnableBtn = document.getElementById('btn-enable-biometric');
  const bioDisableBtn = document.getElementById('btn-disable-biometric');
  if (bioStatus && bioEnableBtn && bioDisableBtn) {
    bioStatus.textContent = biometricEnabled ? 'Attivo su questo dispositivo' : 'Non configurato';
    bioEnableBtn.classList.toggle('hidden', biometricEnabled);
    bioDisableBtn.classList.toggle('hidden', !biometricEnabled);
  }

  const totpStatus = document.getElementById('settings-totp-status');
  const totpEnableBtn = document.getElementById('btn-enable-totp');
  const totpDisableBtn = document.getElementById('btn-disable-totp');
  if (totpStatus && totpEnableBtn && totpDisableBtn) {
    totpStatus.textContent = totpEnabled ? 'Attivo' : 'Non configurato';
    totpEnableBtn.textContent = totpEnabled ? 'Riconfigura' : 'Configura';
    totpDisableBtn.classList.toggle('hidden', !totpEnabled);
  }
}

export function updateSyncStatus(status) {
  const icon = document.getElementById('sync-icon');
  if (!icon) return;
  
  switch(status) {
    case 'synced':
      icon.innerHTML = '<use href="#icon-cloud"></use>';
      icon.parentElement.classList.remove('text-danger', 'text-warning');
      icon.parentElement.classList.add('text-success');
      break;
    case 'syncing':
      icon.innerHTML = '<use href="#icon-refresh"></use>';
      icon.parentElement.classList.remove('text-danger', 'text-success');
      icon.parentElement.classList.add('text-warning');
      // add spin class?
      break;
    case 'error':
      icon.innerHTML = '<use href="#icon-cloud"></use>';
      icon.parentElement.classList.remove('text-success', 'text-warning');
      icon.parentElement.classList.add('text-danger');
      break;
    case 'disconnected':
    default:
      icon.innerHTML = '<use href="#icon-cloud"></use>';
      icon.parentElement.classList.remove('text-success', 'text-warning', 'text-danger');
      break;
  }
}

export function startAutoLockTimer(minutes) {
  clearTimeout(autoLockTimerId);
  if (minutes > 0) {
    autoLockTimerId = setTimeout(() => {
      document.dispatchEvent(new CustomEvent('auto-lock'));
    }, minutes * 60 * 1000);
  }
}

export function resetAutoLockTimer() {
  const settings = JSON.parse(localStorage.getItem('dipavaultguard_settings') || '{}');
  const mins = settings.autoLockMinutes !== undefined ? settings.autoLockMinutes : 5;
  startAutoLockTimer(mins);
}
