var token = ""
var tokenit = "";
window.onload = function () {
    translate()
    loading.style.display = "none";
};
function login(){
    loading.style.display = "block";
    loginform.style.display = "none";
}
$("#recovery_btn_login").click(function(){
    getCookie()
});
function getCookie() {
  var getting = chrome.cookies.get({
  url: "https://isenhas.com.br",
  name: "tokenis"
  });
  getting.then(logCookie);
}
function logCookie(cookie) {
  if (cookie) {
      token = cookie.value;
      authenticate();
  } else {
      localStorage.removeItem("obj")
      localStorage.removeItem("obj1")
      localStorage.removeItem("obj2")
      window.location = "login.html";
  }
}
function authenticate(){
    loading.style.display = "block";
    loginform.style.display = "none";
    
    var xhr = new XMLHttpRequest();
    var url = host+"/iSenhasLoginRecoveryV4";
    if(development) url = host+"/iSenhasLoginRecoveryV4DEV";
    xhr.open("POST", url, true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.setRequestHeader('Access-Control-Allow-Origin', '*');
    xhr.setRequestHeader('authorization', token);
    xhr.onreadystatechange = async function () {
        if (xhr.readyState === 4 && xhr.status === 200) {
          let input = document.getElementById("recovery_nomeedit");
          const d = new Date();
          var time = 168;
          var mytime = d.setTime(d.getTime() + (time*60*60*1000));
          let recoveryEncrypted = await encryptData(input.value.toUpperCase())
          chrome.cookies.set({
            url: "https://isenhas.com.br",
            name: "recovery",
            expirationDate: mytime,
            value: recoveryEncrypted,
            secure: true,
            httpOnly: true,
            sameSite: "strict",
          },function (cookie2){
              window.location = 'senhas.html';
          });
        } else if (xhr.readyState === 4 && xhr.status === 406) {
            spinner.style.display = "none";
            recovery_loadinglabel.innerHTML = chrome.i18n.getMessage("recovery_login_error")+": "+xhr.status;
        } else if(xhr.readyState === 4){
            console.log(xhr.responseText)
            spinner.style.display = "none";
            recovery_loadinglabel.innerHTML = chrome.i18n.getMessage("login_error")+": "+xhr.status;
        }
    };
    let input = document.getElementById("recovery_nomeedit");
    sha256(input.value.toUpperCase()).then(function(resultado) {
        xhr.send("{\"recoverykey\":\""+resultado+"\"}")
    });    
}
function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  return crypto.subtle.digest("SHA-256", msgBuffer)
    .then(hashBuffer => {
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
      return hashHex;
    });
}
function translate(){
  document.getElementById("recovery_title").innerHTML = chrome.i18n.getMessage("recovery_title");
  document.getElementById("recovery_nomeeditlabel").innerHTML = chrome.i18n.getMessage("recovery_key");
  document.getElementById("recovery_nomeedit").placeholder = chrome.i18n.getMessage("recovery_nomeedit");
  document.getElementById("recovery_desc1").innerHTML = chrome.i18n.getMessage("recovery_desc1");
  document.getElementById("recovery_desc2").innerHTML = chrome.i18n.getMessage("loginDesc2");
  document.getElementById("recovery_btn_login").innerHTML = chrome.i18n.getMessage("signIn");
  document.getElementById("recovery_loadinglabel").innerHTML = chrome.i18n.getMessage("recovery_loadinglabel");
}