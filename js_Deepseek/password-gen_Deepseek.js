export function generatePassword(options = {}) {
  const {
    length = 20,
    uppercase = true,
    lowercase = true,
    numbers = true,
    symbols = true,
    excludeAmbiguous = false
  } = options;

  let upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let lowerChars = 'abcdefghijklmnopqrstuvwxyz';
  let numChars = '0123456789';
  let symChars = '!@#$%^&*()_+~`|}{[]:;?><,./-=';
  
  if (excludeAmbiguous) {
    const ambiguous = 'il1Lo0O';
    upperChars = upperChars.split('').filter(c => !ambiguous.includes(c)).join('');
    lowerChars = lowerChars.split('').filter(c => !ambiguous.includes(c)).join('');
    numChars = numChars.split('').filter(c => !ambiguous.includes(c)).join('');
  }

  let chars = '';
  if (uppercase) chars += upperChars;
  if (lowercase) chars += lowerChars;
  if (numbers) chars += numChars;
  if (symbols) chars += symChars;
  
  if (chars.length === 0) {
    chars = lowerChars; // fallback
  }

  let password = '';
  const randomArray = new Uint32Array(length);
  crypto.getRandomValues(randomArray);

  // Guarantee at least one of each selected type if length is sufficient
  let i = 0;
  if (uppercase && i < length) { password += upperChars[randomArray[i] % upperChars.length]; i++; }
  if (lowercase && i < length) { password += lowerChars[randomArray[i] % lowerChars.length]; i++; }
  if (numbers && i < length) { password += numChars[randomArray[i] % numChars.length]; i++; }
  if (symbols && i < length) { password += symChars[randomArray[i] % symChars.length]; i++; }

  for (; i < length; i++) {
    password += chars[randomArray[i] % chars.length];
  }

  // Shuffle the password
  password = password.split('').sort(() => 0.5 - Math.random()).join('');
  
  return password;
}

// A small wordlist for passphrases
const wordlist = [
  "albero", "banca", "cane", "dente", "elefante", "fiume", "gatto", "hotel", "isola", "luna",
  "mare", "nave", "orso", "pane", "quadro", "ruota", "sole", "tavolo", "uccello", "vaso",
  "zaino", "cielo", "fiore", "libro", "mano", "neve", "onda", "piede", "sedia", "treno",
  "vento", "zero", "amico", "bosco", "casa", "dito", "erba", "fuoco", "gioco", "lago",
  "mela", "notte", "ombra", "porta", "ramo", "sasso", "tenda", "uovo", "volpe", "zappa"
];

export function generatePassphrase(options = {}) {
  const {
    wordCount = 4,
    separator = '-',
    capitalize = false
  } = options;

  const randomArray = new Uint32Array(wordCount);
  crypto.getRandomValues(randomArray);

  const words = [];
  for (let i = 0; i < wordCount; i++) {
    let word = wordlist[randomArray[i] % wordlist.length];
    if (capitalize) {
      word = word.charAt(0).toUpperCase() + word.slice(1);
    }
    words.push(word);
  }

  return words.join(separator);
}

export function calculateStrength(password) {
  if (!password) return { score: 0, label: 'Molto debole', entropy: 0, color: '#dc2626' };
  
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;
  
  const entropy = password.length * Math.log2(charsetSize || 1);
  
  let score = 0;
  let label = '';
  let color = '';
  
  if (entropy < 28) {
    score = 1; label = 'Molto debole'; color = '#dc2626'; // Danger
  } else if (entropy < 35) {
    score = 2; label = 'Debole'; color = '#f97316'; // Orange
  } else if (entropy < 59) {
    score = 3; label = 'Buona'; color = '#f59e0b'; // Warning
  } else if (entropy < 120) {
    score = 4; label = 'Forte'; color = '#16a34a'; // Success
  } else {
    score = 5; label = 'Molto forte'; color = '#15803d'; // Dark green
  }
  
  return { score, label, entropy, color };
}
