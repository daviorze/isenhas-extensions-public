function keyFromReadable(readableKey) {
  const cleaned = readableKey.replace(/[- ]/g, "").toUpperCase();
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let keyBytes = [];
  for (let c of cleaned) {
    const idx = charset.indexOf(c);
    if (idx >= 0) {
      keyBytes.push(idx);
    }
  }
  if (keyBytes.length > 32) {
    keyBytes = keyBytes.slice(0, 32);
  } else if (keyBytes.length < 32) {
    keyBytes = keyBytes.concat(new Array(32 - keyBytes.length).fill(0));
  }
  return new Uint8Array(keyBytes);
}
async function importKey(readableKey) {
  const keyBytes = keyFromReadable(readableKey);
  return await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}
async function extremeEncrypt(plainText, readableKey) {
  const key = await importKey(readableKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encoder = new TextEncoder();
  const data = encoder.encode(plainText);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data
  );
  const encryptedBytes = new Uint8Array(encrypted);
  const payload = new Uint8Array(iv.length + encryptedBytes.length);
  payload.set(iv, 0);
  payload.set(encryptedBytes, iv.length);
  return btoa(String.fromCharCode(...payload));
}
async function extremeDecrypt(encryptedBase64, readableKey) {
  try {
    const key = await importKey(readableKey);
    const payload = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

    const iv = payload.slice(0, 12);
    const cipherWithTag = payload.slice(12);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      cipherWithTag
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } catch (err) {
    if (err.name === "OperationError") {
      console.error("Chave incorreta ou payload corrompido no extremeDecrypt.");
      return chrome.i18n.getMessage("wrong_recovery_key");
    } else {
      console.error("Erro inesperado no extremeDecrypt:", err);
      return null;
    }
  }
}
const DB_NAME = "secureVaultDB";
const STORE_NAME = "keys";
const KEY_NAME = "vaultKey";

function base64ToBytes(base64) {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}
function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);

    request.onupgradeneeded = () => {
      request.result.createObjectStore(STORE_NAME);
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function saveKey(cryptoKey) {
  const db = await openDB();
  const tx = db.transaction(STORE_NAME, "readwrite");
  tx.objectStore(STORE_NAME).put(cryptoKey, KEY_NAME);

  return new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onerror = reject;
  });
}
var encryptionKey = null
async function loadKey() {
  if (encryptionKey) return encryptionKey;
  const db = await openDB();
  encryptionKey = await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const request = tx.objectStore(STORE_NAME).get(KEY_NAME);

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  return encryptionKey;
}
async function deleteKey() {
  const db = await openDB();
  const tx = db.transaction(STORE_NAME, "readwrite");
  tx.objectStore(STORE_NAME).delete(KEY_NAME);
}
async function importAndStoreKey(base64Key) {
  const keyBytes = base64ToBytes(base64Key);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );

  await saveKey(cryptoKey);
}
async function encryptData(dataString) {
  const key = await loadKey();
  if (!key) throw new Error("Chave não encontrada");

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(dataString);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );

  const result = new Uint8Array(iv.length + encrypted.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(encrypted), iv.length);

  return bytesToBase64(result);
}
async function decryptData(base64Cipher) {
  const key = await loadKey();
  if (!key) throw new Error("Chave não encontrada");

  const bytes = base64ToBytes(base64Cipher);

  const iv = bytes.slice(0, 12);
  const data = bytes.slice(12);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  return new TextDecoder().decode(decrypted);
}