
chrome.tabs.onUpdated.addListener(async function(tabId, changeInfo, tab) {
  if (changeInfo.status == 'complete'){
    await chrome.storage.session.set({
    ["tab_" + tabId]: tab.url
    });
    chrome.tabs.sendMessage(tabId,{ type: "PAGE_READY" });
  }
});
chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {

  if (req.type === "GET_DATABASE") {
    (async () => {
      const tabId = sender.tab.id;
      const urlData = await chrome.storage.session.get("tab_" + tabId);
      let url = urlData["tab_" + tabId];
      getFromDatabase(url).then(database => {
        sendResponse({ database });
      });
    })();
    return true;
  }
});
async function getFromDatabase(dataurl) {
    var encryptedPasswords = null;
    var todasSenhas = []
    if(await chrome.storage.local.get("obj") != null){
      let databaseRaw = await chrome.storage.local.get("obj")
      encryptedPasswords = JSON.parse(databaseRaw.obj);
    }
    if (encryptedPasswords != null) {
        for (var i = 0; i < encryptedPasswords.length; i++) {
            var decoded = await decryptData(encryptedPasswords[i].fields.password.value);
            encryptedPasswords[i].fields.password.value = decoded
            encryptedPasswords[i].fields.name.value = await decryptData(encryptedPasswords[i].fields.name.value);
            if (encryptedPasswords[i].fields.observation)
                encryptedPasswords[i].fields.observation.value = await decryptData(encryptedPasswords[i].fields.observation.value);
            if (encryptedPasswords[i].fields.old)
                encryptedPasswords[i].fields.old.value = await decryptData(encryptedPasswords[i].fields.old.value);
        }
        todasSenhas = encryptedPasswords;
    }
    await delay(1000);
    let response = await filterElements(todasSenhas,dataurl);
    return response
}
chrome.tabs.onRemoved.addListener((tabId) => {
  readyTabs.delete(tabId);
  chrome.storage.session.remove("tab_" + tabId);
});
function delay(time) {
    return new Promise(resolve => setTimeout(resolve, time));
}
async function filterElements(todasSenhas,dataurl) {
    throw new Error("Proprietary module");
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
function getListIconFromText(text){
    throw new Error("Proprietary module");
}
function isMatch(searchOnString, searchText) {
    searchText = searchText.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
    return searchOnString.match(new RegExp("\\b"+searchText+"\\b", "i")) != null;
}