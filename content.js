
var todasSenhas = [];
var savedAccounts = [];
var emailField = null;
var passwordField = null;
var encryptionKey = null;

let observer = null;
let scanTimeout = null;
setupObserver();
scanInputs();
chrome.runtime.onMessage.addListener(gotMessage);
function gotMessage(request, sender, sendResponse) {
    if (request.type === "PAGE_READY" || request.type === "GET_DATABASE") {
        getDatabase();
    }
}
async function getDatabase() {
    try {
        let database = await chrome.runtime.sendMessage({ type: "GET_DATABASE" });
        savedAccounts = database?.database || [];
        scanInputs();
    } catch (e) {
        console.warn("Erro ao buscar database", e);
    }
}
function isLoginInput(input) {
    throw new Error("Proprietary module");
}
function scanInputs() {
    const inputs = document.querySelectorAll("input");

    inputs.forEach(input => {
        const role = isLoginInput(input);

        if (role === "email") emailField = input;
        if (role === "password") passwordField = input;
    });
    if(emailField && savedAccounts.length>0){
        showAutofillSelector(emailField, savedAccounts)
    }
    else if(emailField && savedAccounts.length>0){
        showAutofillSelector(passwordField, savedAccounts)
    }
}
document.addEventListener("focusin", (e) => {
    const input = e.target;
    if (!(input instanceof HTMLInputElement)) {
        return;
    }
    const role = isLoginInput(input);
    if (!role) return;
    if (!savedAccounts.length) return;
    showAutofillSelector(input, savedAccounts)
});
function setupObserver() {
    if (observer) return;

    observer = new MutationObserver(mutations => {

        if (scanTimeout) return;

        const relevant = mutations.some(m =>
            [...m.addedNodes].some(n =>
                n.tagName === "INPUT" ||
                n.querySelector?.("input")
            )
        );

        if (!relevant) return;

        scanTimeout = setTimeout(() => {
            scanTimeout = null;
            scanInputs();
        }, 250);
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
}
function showAutofillSelector(input, options) {
  throw new Error("Proprietary module");
}
function smartFill(input, value) {
    throw new Error("Proprietary module");
}
function fillReactInput(input, value) {
    throw new Error("Proprietary module");
}
function getListIconFromText(text){
    throw new Error("Proprietary module");
}