var token = "";
var tokenit = "";
var recoverykey = ""
var passwords;
var todasSenhas = [];
var numeroSenhas = 0;
var vaults = []
var editSelected = 0;
var enviado = 0;
var onLoad = false;
var selectedRows = [];
const title = document.getElementById("title");
const desc1 = document.getElementById("desc1");
const desc2 = document.getElementById("desc2");
const button = document.getElementById("button");
const loading = document.getElementById("loading");
const form = document.getElementById("form");
const loadinglabel = document.getElementById("loadinglabel");
const spinner = document.getElementById("spinner");
const table = document.getElementById("tabela");
const search = document.getElementById("search");
var slider = document.getElementById("myRange");
var output = document.getElementById("lengthPass");
var maiusculas = document.getElementById("maiusculas");
var minusculas = document.getElementById("minusculas");
var caracteres = document.getElementById("caracteres");
var numeros = document.getElementById("numeros");
var sliderEdit = document.getElementById("myRangeEdit");
var outputEdit = document.getElementById("lengthPassEdit");
var maiusculasEdit = document.getElementById("maiusculasEdit");
var minusculasEdit = document.getElementById("minusculasEdit");
var caracteresEdit = document.getElementById("caracteresEdit");
var numerosEdit = document.getElementById("numerosEdit");
var reloadbutton = false;
var isExtreme = false
async function totp(key ,secs = 30, digits = 6,algorithm = "SHA-1"){
	return hotp(unbase32(key), pack64bu(Date.now() / 1000 / secs), digits,algorithm)
  
}
async function hotp(key, counter, digits,algorithm){
	let y = self.crypto.subtle;
	if(!y) throw Error('no self.crypto.subtle object available');
	let k = await y.importKey('raw', key, {name: 'HMAC', hash: algorithm}, false, ['sign']);
	return hotp_truncate(await y.sign('HMAC', k, counter), digits);
}
function hotp_truncate(buf, digits){
	let a = new Uint8Array(buf), i = a[19] & 0xf;
	return fmt(10, digits, ((a[i]&0x7f)<<24 | a[i+1]<<16 | a[i+2]<<8 | a[i+3]) % 10**digits);
}

function fmt(base, width, num){
	return num.toString(base).padStart(width, '0')
}
function unbase32(s){
	let t = (s.toLowerCase().match(/\S/g)||[]).map(c => {
		let i = 'abcdefghijklmnopqrstuvwxyz234567'.indexOf(c);
		if(i < 0) throw Error(`bad char '${c}' in key`);
		return fmt(2, 5, i);
	}).join('');
	if(t.length < 8) throw Error('key too short');
	return new Uint8Array(t.match(/.{8}/g).map(d => parseInt(d, 2)));
}
function pack64bu(v){
	let b = new ArrayBuffer(8), d = new DataView(b);
	d.setUint32(0, v / 2**32);
	d.setUint32(4, v);
	return b;
}

window.onload = function () {
  document.getElementById("buttonlogout").addEventListener("click", logout);
  document.getElementById("buttonclose").addEventListener("click", buttonclose);
  document.getElementById("buttonadd").addEventListener("click", add);
  document.getElementById("buttonremove").addEventListener("click", excluir);
  document.getElementById("gerarsenha").addEventListener("click", gerarsenha);
  document.getElementById("addadd").addEventListener("click", buttonadicionar);
  document.getElementById("removeremove").addEventListener("click", buttonremove);
  document.getElementById("buttonreload").addEventListener("click", buttonreload);
  document.getElementById("gerarsenhaedit").addEventListener("click", gerarsenhaedit);
  document.getElementById("saveedit").addEventListener("click", buttoneditar);
  document.getElementById("search").addEventListener("keyup", searchPass);
  document.getElementById("hideaddlabel").addEventListener("click", hideadd);
  document.getElementById("hideeditlabel").addEventListener("click", hideedit);
  document.getElementById("senhaadd").addEventListener('input', function (evt) {
    updateInput(this.value);
  });
  document.getElementById("senhaedit").addEventListener('input', function (evt) {
    updateInput(this.value);
  });

  translate();
  loading.style.display = "block";
  limiter.style.display = "none";
  getCookie();
};
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
      getCookie3();
  } else {
      localStorage.removeItem("obj")
      localStorage.removeItem("obj1")
      localStorage.removeItem("obj2")
      window.location = "login.html";
  }
}
function getCookie3() {
  var getting = chrome.cookies.get({
  url: "https://isenhas.com.br",
  name: "recovery"
  });
  getting.then(logCookie3);
}
async function logCookie3(cookie) {
  if (cookie) {
      if(cookie.value == "none"){
        getFromDatabase();
      } else if(cookie.value == "wait"){
        localStorage.removeItem("obj")
        localStorage.removeItem("obj2")
        localStorage.removeItem("obj1")
        window.location = "recoverykey.html";
      } else {
        isExtreme = true
        recoverykey = await decryptData(cookie.value);
        getFromDatabase();
      } 
  } else {
      getFromDatabase();
  }
}
async function getFromDatabase() {
  var encryptedPasswords = JSON.parse(localStorage.getItem("obj"));
  var encryptedVaults = JSON.parse(localStorage.getItem("obj2"));
  if (encryptedPasswords == null){
    reloadbutton = true
    getPasswords()
  } else {
    try{
      if (encryptedPasswords != null) {
        await Promise.all(encryptedPasswords.map(async (rec) => {
          var sharedItem = false
          if(rec.fields.admin || rec.fields.sharedDesc){
              sharedItem = true
          }
          rec.fields.password.value = await decryptData(rec.fields.password.value)
          rec.fields.name.value = await decryptData(rec.fields.name.value);
          if (rec.fields.observation) {
            rec.fields.observation.value = await decryptData(rec.fields.observation.value);
          }
          if (rec.fields.description) {
            rec.fields.description.value = await decryptData(rec.fields.description.value);
          }
          if (rec.fields.old) {
            rec.fields.old.value = await decryptData(rec.fields.old.value);            
          }
          if (rec.fields.secret) {
            rec.fields.secret.value = await decryptData(rec.fields.secret.value);
          }
          if (rec.fields.period) {
            rec.fields.period.value = await decryptData(rec.fields.period.value);
          }
          if (rec.fields.algorithm) {
            rec.fields.algorithm.value = await decryptData(rec.fields.algorithm.value);
          }
          if (rec.fields.digits) {
            rec.fields.digits.value = await decryptData(rec.fields.digits.value);
          }
          if (rec.fields.vaultid) {
            rec.fields.vaultid.value = await decryptData(rec.fields.vaultid.value);
          }
          if(rec.fields.sharedDesc){
            rec.fields.sharedDesc.value = await decryptData(rec.fields.sharedDesc.value);
          }
        }));
        todasSenhas = encryptedPasswords;
      }
      if (encryptedVaults != null) {
        for (var i = 0; i < encryptedVaults.length; i++) {
          encryptedVaults[i].name = await decryptData(encryptedVaults[i].name);
        }
        vaults = encryptedVaults;
        let vault = {"recordName":"0","name":chrome.i18n.getMessage("personal")}
        vaults.unshift(vault)
      } else {
        let vault = {"recordName":"0","name":chrome.i18n.getMessage("personal")}
        vaults.unshift(vault)
      }
      setInterval(reloadProgress, 1000);
    } catch(error){
        console.error("Error while get items: "+error)
        reloadbutton = true
        getPasswords()
    }
    reloadTable();
  }
}
slider.oninput = function() {
  output.innerHTML = this.value;
}
slider.onchange = function() {
  gerarsenha()
}
maiusculas.onchange = function() {
  gerarsenha()
}
minusculas.onchange = function() {
  gerarsenha()
}
numeros.onchange = function() {
  gerarsenha()
}
caracteres.onchange = function() {
  gerarsenha()
}
sliderEdit.oninput = function() {
  outputEdit.innerHTML = this.value;
}
sliderEdit.onchange = function() {
  gerarsenhaedit()
}
maiusculasEdit.onchange = function() {
  gerarsenhaedit()
}
minusculasEdit.onchange = function() {
  gerarsenhaedit()
}
numerosEdit.onchange = function() {
  gerarsenhaedit()
}
caracteresEdit.onchange = function() {
  gerarsenhaedit()
}
async function decryptExtreme(value){
  var decrypted = await extremeDecrypt(value, recoverykey);
  return decrypted
}
async function encryptExtreme(value){
  var decrypted = await extremeEncrypt(value, recoverykey);
  return decrypted
}
async function getPasswords() {
  todasSenhas = [];
  loadinglabel.innerHTML = chrome.i18n.getMessage("search_passwords") + "...";
  var xhr = new XMLHttpRequest();
  var url = host + "/iSenhasBuscarSenhasV4";
  if (development) url = host + "/iSenhasBuscarSenhasV4DEV";
  xhr.open("POST", url, true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.setRequestHeader('Access-Control-Allow-Origin', '*');
  xhr.setRequestHeader('authorization', token);

  xhr.onreadystatechange = async function () {
    if (xhr.readyState === 4 && xhr.status === 200) {
      var objResponse = JSON.parse(xhr.responseText);
      var records = objResponse.passwords;
      if (records.length == 0) {
        limiter.style.display = "block";
        loading.style.display = "none";
      } else {
        try{
        var recordsToSave = []
        await Promise.all(records.map(async (rec) => {
          var recordToSave = structuredClone(rec)
          var sharedItem = false
          if(rec.fields.admin){
              sharedItem = true
          }
          rec.fields.password.value = window.atob(rec.fields.password.value);
          if (isExtreme && !sharedItem) {
            rec.fields.password.value = await extremeDecrypt(rec.fields.password.value, recoverykey);
          }
          recordToSave.fields.password = {"value": await encryptData(rec.fields.password.value)}
          if (isExtreme && !sharedItem) {
            rec.fields.name.value = await extremeDecrypt(rec.fields.name.value, recoverykey);
          }
          recordToSave.fields.name = {"value": await encryptData(rec.fields.name.value)}
          if (rec.fields.observation) {
            if (isExtreme && !sharedItem) {
              rec.fields.observation.value = await extremeDecrypt(rec.fields.observation.value, recoverykey);
            }
            recordToSave.fields.observation = {"value": await encryptData(rec.fields.observation.value)}
          }
          if (rec.fields.description) {
            if (isExtreme && !sharedItem) {
              rec.fields.description.value = await extremeDecrypt(rec.fields.description.value, recoverykey);
            }
            recordToSave.fields.description = {"value": await encryptData(rec.fields.description.value)}
          }
          if (rec.fields.old) {
            rec.fields.old.value = window.atob(rec.fields.old.value);
            if (isExtreme && !sharedItem) {
              rec.fields.old.value = await extremeDecrypt(rec.fields.old.value, recoverykey);
            }
            recordToSave.fields.old = {"value": await encryptData(rec.fields.old.value)}
          }
          if (rec.fields.secret) {
            if (isExtreme && !sharedItem) {
              rec.fields.secret.value = await extremeDecrypt(rec.fields.secret.value, recoverykey);
            }
            recordToSave.fields.secret = {"value": await encryptData(rec.fields.secret.value)}
          }
          if (rec.fields.period) {
            if (isExtreme && !sharedItem) {
              rec.fields.period.value = await extremeDecrypt(rec.fields.period.value, recoverykey);
            }
            recordToSave.fields.period = {"value": await encryptData(rec.fields.period.value)}
          }
          if (rec.fields.algorithm) {
            if (isExtreme && !sharedItem) {
              rec.fields.algorithm.value = await extremeDecrypt(rec.fields.algorithm.value, recoverykey);
            }
            recordToSave.fields.algorithm = {"value": await encryptData(rec.fields.algorithm.value)}
          }
          if (rec.fields.digits) {
            if (isExtreme && !sharedItem) {
              rec.fields.digits.value = await extremeDecrypt(rec.fields.digits.value, recoverykey);
            }
            recordToSave.fields.digits = {"value": await encryptData(rec.fields.digits.value)}
          }
          if (rec.fields.vaultid) {
            recordToSave.fields.vaultid = {"value": await encryptData(rec.fields.vaultid.value)}
          }
          recordsToSave.push(recordToSave)
        }));
        todasSenhas = records;
        localStorage.setItem("obj", JSON.stringify(recordsToSave));
        chrome.storage.local.set({"obj":JSON.stringify(recordsToSave)});
        loadinglabel.innerHTML = chrome.i18n.getMessage("search_passwords") + ": " + todasSenhas.length;
        if(reloadbutton == true){
          getVaults()
          reloadbutton = false
        } else {
          getShared()
        }
        } catch(error){
          console.error("Error while get items: "+error)
          localStorage.removeItem("obj")
          localStorage.removeItem("obj2")
          chrome.storage.local.remove(["obj","obj2"])
          chrome.cookies.remove({
              url: "https://isenhas.com.br",
              name: "tokenis"
            }).then(() => {
              return chrome.cookies.remove({
                url: "https://isenhas.com.br",
                name: "recovery"
              });
            }).then(() => {
              window.location = "login.html";
            });
          await deleteKey();
      }
      }
    } else if (xhr.readyState === 4 && xhr.status === 401) {
      spinner.style.display = "none";
      window.location = 'login.html';
    } else if (xhr.readyState === 4) {
      spinner.style.display = "none";
      var language = navigator.language || navigator.userLanguage;
      loadinglabel.innerHTML = chrome.i18n.getMessage("search_passwords_error") + ": " + xhr.status;
    }
  };

  xhr.send();
}
function getVaults() {
  vaults = [];
  loadinglabel.innerHTML = chrome.i18n.getMessage("search_vaults") + "...";
  var xhr = new XMLHttpRequest();
  var url = host + "/iSenhasBuscarCofresV4";
  if (development) url = host + "/iSenhasBuscarCofresV4DEV";
  xhr.open("POST", url, true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.setRequestHeader('Access-Control-Allow-Origin', '*');
  xhr.setRequestHeader('authorization', token);

  xhr.onreadystatechange = async function () {
    if (xhr.readyState === 4 && xhr.status === 200) {
      var objResponse = JSON.parse(xhr.responseText);
      var records = objResponse.vaults;
      if (records.length == 0) {
        limiter.style.display = "block";
        loading.style.display = "none";
        setInterval(reloadProgress, 1000);
        let vault = {"recordName":"0","name":chrome.i18n.getMessage("personal")}
        vaults.unshift(vault)
        reloadTable();
      } else {
        var isShared = false
        var recordsToSave = []
        for (var i = 0; i < records.length; i++) {
          var recordToSave = {}
          recordToSave = structuredClone(records[i])
          recordToSave.name = await encryptData(records[i].name);
          if(records[i].admin != null){
            isShared = true
          }
          recordsToSave.push(recordToSave)
        }
        vaults = records;
        localStorage.setItem("obj2", JSON.stringify(recordsToSave));
        chrome.storage.local.set({"obj2":JSON.stringify(recordsToSave)});
        let vault = {"recordName":"0","name":chrome.i18n.getMessage("personal")}
        vaults.unshift(vault)
        if(isShared){
          getShared()
        } else {
          limiter.style.display = "block";
          loading.style.display = "none";
          setInterval(reloadProgress, 1000);
          reloadTable();
        }
      }
    } else if (xhr.readyState === 4 && xhr.status === 401) {
      spinner.style.display = "none";
      window.location = 'login.html';
    } else if (xhr.readyState === 4) {
      spinner.style.display = "none";
      var language = navigator.language || navigator.userLanguage;
      loadinglabel.innerHTML = chrome.i18n.getMessage("search_passwords_error") + ": " + xhr.status;
    }
  };

  xhr.send();
}
function getShared() {
  loadinglabel.innerHTML = chrome.i18n.getMessage("search_passwords")+"...";
  var xhr = new XMLHttpRequest();
  var url = host+"/iSenhasBuscarCofresCompartilhadoV4";
  if(development) url = host+"/iSenhasBuscarCofresCompartilhadoV4DEV";
  xhr.open("POST", url, true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.setRequestHeader('Access-Control-Allow-Origin', '*');
  xhr.setRequestHeader('authorization', token);

  xhr.onreadystatechange =  async function () {
    if (xhr.readyState === 4 && xhr.status === 200) {
      var objResponse = JSON.parse(xhr.responseText);
      var records = objResponse.items;
      if (records.length == 0) {
        limiter.style.display = "block";
        loading.style.display = "none";
        setInterval(reloadProgress, 1000);
        reloadTable();
      } else {
        for(i in objResponse.items){
          objResponse.items[i].fields.sharedDesc = {"value":await encryptData(chrome.i18n.getMessage("shared_by")+" "+ objResponse.items[i].fields.user.value)}
        }
        var recordsToSave = structuredClone(records)
        for(var i=0;i<records.length;i++){
          var recordToSave = structuredClone(records[i])
          records[i].fields.password.value = window.atob(records[i].fields.password.value)
          recordToSave[i].fields.password.value = await encryptData(records[i].fields.password.value)
          recordToSave[i].fields.name.value = await encryptData(records[i].fields.name.value)
          if(records[i].fields.observation)
            recordToSave[i].fields.observation.value = await encryptData(records[i].fields.observation.value)
          if(records[i].fields.description)
            recordToSave[i].fields.description.value = await encryptData(records[i].fields.description.value)
          if(records[i].fields.old){
            records[i].fields.old.value = window.atob(records[i].fields.old.value);
            recordToSave[i].fields.old.value = await encryptData(records[i].fields.old.value)
          }
          if(records[i].fields.secret)
            recordToSave[i].fields.secret.value = await encryptData(records[i].fields.secret.value)
          if(records[i].fields.period)
            recordToSave[i].fields.period.value = await encryptData(records[i].fields.period.value)
          if(records[i].fields.algorithm)
            recordToSave[i].fields.algorithm.value = await encryptData(records[i].fields.algorithm.value)
          if(records[i].fields.digits)
            recordToSave[i].fields.digits.value = await encryptData(records[i].fields.digits.value)
          if(records[i].fields.vaultid)
            recordToSave[i].fields.vaultid.value = await encryptData(records[i].fields.vaultid.value)
          records[i].fields.sharedDesc = {"value":(chrome.i18n.getMessage("shared_by")+" "+ records[i].fields.user.value)}
          recordsToSave.push(recordToSave)
        }
        Array.prototype.push.apply(todasSenhas, records);
        var encryptedPasswords = JSON.parse(localStorage.getItem("obj"));
        Array.prototype.push.apply(encryptedPasswords, recordsToSave);
        localStorage.setItem("obj", JSON.stringify(encryptedPasswords));
        chrome.storage.local.set({"obj":JSON.stringify(encryptedPasswords)});
        limiter.style.display = "block";
        loading.style.display = "none";
        setInterval(reloadProgress, 1000);
        reloadTable();
      }
    } else if (xhr.readyState === 4 && xhr.status === 401) {
      spinner.style.display = "none";
      window.location = 'login.html';
    } else if (xhr.readyState === 4) {
      spinner.style.display = "none";
      loadinglabel.innerHTML = chrome.i18n.getMessage("search_passwords_error")+": " + xhr.status;
    }
  };

  xhr.send(""+JSON.stringify({"type":"password"}));
}
async function logout() {
  localStorage.removeItem("obj")
  localStorage.removeItem("obj2")
  chrome.storage.local.remove(["obj","obj2"])
  chrome.cookies.remove({
      url: "https://isenhas.com.br",
      name: "tokenis"
    }).then(() => {
      return chrome.cookies.remove({
        url: "https://isenhas.com.br",
        name: "recovery"
      });
    }).then(() => {
      window.location = "login.html";
    });
  await deleteKey();
}
function buttonreload() {
  localStorage.removeItem("obj")
  localStorage.removeItem("obj2")
  todasSenhas = [];
  vaults = []
  loading.style.display = "block";
  limiter.style.display = "none";
  reloadbutton = true
  getPasswords();
}
async function reloadProgress(){
  var favorites = []
  var others = []
  for(var v=0;v<todasSenhas.length;v++){
    let fav = todasSenhas[v]["fields"]["favorite"]
    if(fav == null){
      others.push(todasSenhas[v])
    } else {
      favorites.push(todasSenhas[v])
    }
  }
  others.sort(function(a, b) {
    return (a.modified > b.modified) ? -1 : ((a.modified < b.modified) ? 1 : 0);
  });

  favorites.sort(function(a, b) {
    return (a.modified > b.modified) ? -1 : ((a.modified < b.modified) ? 1 : 0);
  });
  todasSenhas = []
  Array.prototype.push.apply(todasSenhas, favorites);
  Array.prototype.push.apply(todasSenhas, others);
  for(var i=0;i<todasSenhas.length;i++){
      let password = todasSenhas[i]
      if(password.fields.secret != null){
      let fields = password.fields
      
      const t = Date.now() / 1000;
      var v = Math.round(30 - (t % 30))
      let progressid = "circular-progress" + (i+1).toString()
      var progress = document.getElementById(progressid)
      let percent = (v/30)*100
      progress.style.background = `conic-gradient(#fff ${percent * 3.6}deg, #262628 0deg)`;
      let pvalue = "progress-value" + (i+1).toString()
      document.getElementById(pvalue).innerHTML = v.toString()
        var algorithm = fields.algorithm.value
        if(algorithm == "SHA1"){
          algorithm = "SHA-1"
        } else if (algorithm == "SHA256"){
          algorithm = "SHA-256"
        } else if (algorithm == "SHA512"){
          algorithm = "SHA-512"
        }
        let value = await totp(fields.secret.value,fields.period.value,fields.digits.value,algorithm)
        let code = "code" + (i+1).toString()
        document.getElementById(code).innerHTML = value
      
    } 
  }
}
function refreshOptions(){
  var d = document.getElementById("vaultaddoptions");
  removeAll(d)
  vaults.forEach(vault => {
    var vaultid = vault.recordName;
    var name = vault.name;
    var option = document.createElement("option");
      option.text = name
      option.value = vaultid
      option.tag
      d.add(option);
  });
  $("#vaultaddoptions").selectpicker("refresh");

  var e = document.getElementById("vaulteditoptions");
  removeAll(e)
  vaults.forEach(vault => {
    var vaultid = vault.recordName;
    var name = vault.name;
    var option = document.createElement("option");
      option.text = name
      option.value = vaultid
      option.tag
      e.add(option);
  });
  $("#vaulteditoptions").selectpicker("refresh");
}
function removeAll(selectBox) {
  while (selectBox.options.length > 0) {
      selectBox.remove(0);
  }
}      
async function reloadTable() {
  $('#table-body').empty();
  var favorites = []
  var others = []
  for(var v=0;v<todasSenhas.length;v++){
    let fav = todasSenhas[v]["fields"]["favorite"]
    if(fav == null){
      others.push(todasSenhas[v])
    } else {
      favorites.push(todasSenhas[v])
    }
  }
  others.sort(function(a, b) {
    return (a.modified > b.modified) ? -1 : ((a.modified < b.modified) ? 1 : 0);
  });

  favorites.sort(function(a, b) {
    return (a.modified > b.modified) ? -1 : ((a.modified < b.modified) ? 1 : 0);
  });
  todasSenhas = []
  Array.prototype.push.apply(todasSenhas, favorites);
  Array.prototype.push.apply(todasSenhas, others);  
  for (var i = 0; i < todasSenhas.length; i++) {
    var password = todasSenhas[i];
    var display_star = "none"
    if(password.fields.favorite !=null)display_star = "block"
    var named = password.fields.name.value;
    var observation = "-";
    var type = "-";
    if (password.fields.observation != null) observation = password.fields.observation.value;
    if (password.fields.type != null) type = password.fields.type.value;
    var pass = password.fields.password.value
    var image = getListIconFromText(named).image;
    if (type == "note") image = "note";
    var vaultid = "0"
    if(password.fields.vaultid != null){
      vaultid = password.fields.vaultid.value
    }
    var vaultName = chrome.i18n.getMessage("personal")
    for (var x = 0; x < vaults.length; x++){
      let currentid = vaults[x].recordName
      if(currentid == vaultid){
        vaultName = vaults[x].name
      }
    }
    var display = "none"
    if(vaults.length>0){
      display = "block"
    }
    if (!password.fields.admin && !password.fields.sharedDesc) {
      $('#table-body').append(`
                <tr class="rows" id='${i + 1}'>            
                  <td class= "info" id="name${i + 1}">
                    <div style="display: flex;">   
                      <img style="display:${display_star};position:absolute;z-index: 1000;height:14px;margin-right:10px;" alt="Qries" src="../images/iconsmart/star.png" data-toggle="modal" data-target="#exampleModal" data-whatever="@fat"/>
                      <img style="height:24px;margin-right:10px;" alt="Qries" src="../images/iconsmart/${image}.png" data-toggle="modal" data-target="#exampleModal" data-whatever="@fat" onClick= "copy(${i + 1})"/>
                    <div>
                    <div>${named}</div>
                      <div id="passvault${i + 1}" style="font-size:10px;margin-top:5px;display:${display}">${vaultName}</div>
                    </div>
                  </div>
                    </td>
                  <td class= "info" id="observation${i + 1}" style="max-width:100px;word-wrap: break-word;">${observation}</td>
                  <td class= "info" id="pass${i+1}" onclick="select(${i+1})">
                      <input id="password" class="passwordRow" type="password" id="password"value="${pass}" readonly/>
                      <div id="dash${i+1}" onclick="select(${i+1})">━━━━━━━━━━</div>
                      <div  style="display:flex">
                        <div id="code${i+1}" onclick="select(${i+1})">-</div>
                        <div class="circular-progress" id="circular-progress${i+1}">
                          <span class="progress-value" id="progress-value${i+1}">50</span>
                        </div>
                      </div>
                    </td>     
                  <td class= "info" style="text-align:left;width:50px">
                      <i class="fas fa-eye-slash" id="showHide${i + 1}"></i>
                  </td> 
                  <td class= "info"> 
                    <i class="far fa-copy" id= "copy${i+1}"></i>
                    <div id="dashe${i+1}" onclick="select(${i+1})">━</div>
                    <i id="copye${i+1}" class="far fa-copy"></i>
                  </td>
                  <td class= "info" style="text-align:left;">
                  <i class="fas fa-edit" id="edit${i + 1}"></i>
                  </td>
                  <td class= "info" id="recordName" style="display: none;">${password.recordName}</td>
                  <td class= "info" id="recordChangeTag" style="display: none;">${password.recordChangeTag}</td>
                </tr>
            `)
            if(password.fields.secret != null){
              let fields = password.fields
              var algorithm = fields.algorithm.value
              if(algorithm == "SHA1"){
                algorithm = "SHA-1"
              } else if (algorithm == "SHA256"){
                algorithm = "SHA-256"
              } else if (algorithm == "SHA512"){
                algorithm = "SHA-512"
              }
              let value = await totp(fields.secret.value,fields.period.value,fields.digits.value,algorithm)
              let code = "code" + (i+1).toString()
              document.getElementById(code).innerHTML = value
              const t = Date.now() / 1000;
              var v = Math.round(30 - (t % 30))
              let progressid = "circular-progress" + (i+1).toString()
              var progress = document.getElementById(progressid)
              let percent = (v/30)*100
              progress.style.background = `conic-gradient(#fff ${percent * 3.6}deg, #262628 0deg)`;
              let pvalue = "progress-value" + (i+1).toString()
              document.getElementById(pvalue).innerHTML = v.toString()
            } else {
              let code = "code" + (i+1).toString()
              removeElement(code)
              let progressid = "circular-progress" + (i+1).toString()
              removeElement(progressid)
              let dash = "dash" + (i+1).toString()
              removeElement(dash)
              let copy2 = "copye" + (i+1).toString()
              removeElement(copy2)
              let dash2 = "dashe" + (i+1).toString()
              removeElement(dash2)
            }
    } else {
      var subtitle = "" 
      if(password.fields.admin != null)
        subtitle = chrome.i18n.getMessage("shared_by")+" "+password.fields.admin.value
      else
        subtitle = password.fields.sharedDesc.value
      $('#table-body').append(`
          <tr class="rows" id='${i + 1}'>            
            <td class= "info" id="name${i + 1}">
            <div style="display: flex;">   
            <img style="height:24px;margin-right:10px;" alt="Qries" src="../images/iconsmart/${image}.png" data-toggle="modal" data-target="#exampleModal" data-whatever="@fat" onClick= "copy(${i + 1})"/>
            <div>
            <div>${named}</div>
              <div id="passdesc${i + 1}" style="font-size:10px;margin-top:5px;">${subtitle}</div>
            </div>
          </div>
            </td>
            <td class= "info" id="observation${i + 1}" style="max-width:100px;word-wrap: break-word;">${observation}</td>
            <td class= "info" id="pass${i+1}" onclick="select(${i+1})">
                <input id="password" class="passwordRow" type="password" id="password"value="${pass}" readonly/>
                <div id="dash${i+1}" onclick="select(${i+1})">━━━━━━━━━━</div>
                <div  style="display:flex">
                  <div id="code${i+1}" onclick="select(${i+1})">-</div>
                  <div class="circular-progress" id="circular-progress${i+1}">
                    <span class="progress-value" id="progress-value${i+1}">50</span>
                  </div>
                </div>
              </td>     
            <td class= "info" style="text-align:left;width:50px">
                <i class="fas fa-eye-slash" id="showHide${i + 1}"></i>
            </td> 
            <td class= "info" > 
                      <i class="far fa-copy" id= "copy${i+1}"></i>
                      <div id="dashe${i+1}" onclick="select(${i+1})">━</div>
                      <i id="copye${i+1}" class="far fa-copy"></i>
                    </td>
            <td class= "info" style="text-align:left;">
            <i class="fas fa-edit" id="edit${i + 1}"></i>
            </td>
            <td class= "info" id="recordName" style="display: none;">${password.recordName}</td>
            <td class= "info" id="recordChangeTag" style="display: none;">${password.recordChangeTag}</td>
          </tr>
      `)
      if(password.fields.secret != null){
        let fields = password.fields
        var algorithm = fields.algorithm.value
        if(algorithm == "SHA1"){
          algorithm = "SHA-1"
        } else if (algorithm == "SHA256"){
          algorithm = "SHA-256"
        } else if (algorithm == "SHA512"){
          algorithm = "SHA-512"
        }
        let value = await totp(fields.secret.value,fields.period.value,fields.digits.value,algorithm)
        let code = "code" + (i+1).toString()
        document.getElementById(code).innerHTML = value
        const t = Date.now() / 1000;
        var v = Math.round(30 - (t % 30))
        let progressid = "circular-progress" + (i+1).toString()
        var progress = document.getElementById(progressid)
        let percent = (v/30)*100
        progress.style.background = `conic-gradient(#fff ${percent * 3.6}deg, #262628 0deg)`;
        let pvalue = "progress-value" + (i+1).toString()
        document.getElementById(pvalue).innerHTML = v.toString()
      } else {
        let code = "code" + (i+1).toString()
        removeElement(code)
        let progressid = "circular-progress" + (i+1).toString()
        removeElement(progressid)
        let dash = "dash" + (i+1).toString()
        removeElement(dash)
        let copy2 = "copye" + (i+1).toString()
        removeElement(copy2)
        let dash2 = "dashe" + (i+1).toString()
        removeElement(dash2)
      }
    }
    document.getElementById("name" + (i + 1)).addEventListener("click", function () {
      select(this.id.replaceAll("name", ""))
    });
    document.getElementById("observation" + (i + 1)).addEventListener("click", function () {
      select(this.id.replaceAll("observation", ""))
    });
    document.getElementById("pass" + (i + 1)).addEventListener("click", function () {
      select(this.id.replaceAll("pass", ""))
    });
    document.getElementById("copy" + (i + 1)).addEventListener("click", function () {
      copy(this.id.replaceAll("copy", ""))
    });
    if(password.fields.secret != null){
      document.getElementById("copye" + (i + 1)).addEventListener("click", function () {
        copye(this.id.replaceAll("copye", ""))
      });
    }
    document.getElementById("showHide" + (i + 1)).addEventListener("click", function () {
      showHide(this.id.replaceAll("showHide", ""))
    });
    document.getElementById("edit" + (i + 1)).addEventListener("click", function () {
      edit(this.id.replaceAll("edit", ""))
    });
  }
  loading.style.display = "none";
  limiter.style.display = "block";
}
function removeElement(id) {
  var elem = document.getElementById(id);
  return elem.parentNode.removeChild(elem);
}
function searchPass() {
  var input, filter, table, tr, td, i, txtValue;
  var counter = 0
  input = document.getElementById("search");
  filter = input.value.toUpperCase();
  table = document.getElementById("table-body");
  tr = table.getElementsByTagName("tr");
  for (i = 0; i < tr.length; i++) {
    td = tr[i].getElementsByTagName("td")[0];
    if (td) {
      txtValue = td.textContent || td.innerText;
      if (txtValue.toUpperCase().indexOf(filter) > -1) {
        tr[i].style.display = "";
      } else {
        tr[i].style.display = "none";
        counter++;
      }
    }
  }
  if(counter == tr.length && onLoad){
    input.value = ""
    for (i = 0; i < tr.length; i++) {
        td = tr[i].getElementsByTagName("td")[0];
        if (td) {
            tr[i].style.display = "";
        }
    }
    var close = document.getElementById("buttonclose")
    close.style.display = "none"
  }
  if(input.value.length > 0){
    var close = document.getElementById("buttonclose")
    close.style.display = ""
  }
  onLoad = false
}
function showHide(id) {
  //console.log(id);
  var tr = table.getElementsByTagName("tr");
  var td = tr[id].getElementsByTagName("td")[2];
  var tdimage = tr[id].getElementsByTagName("td")[3];
  if (td) {
    var img = tdimage.getElementsByTagName("i")[0];
    var p = td.getElementsByTagName("input")[0];
    //console.log("Password img: " + img.className);
    if (p.type == "password") {
      p.type = "text";
      img.className = "fas fa-eye";
    } else {
      p.type = "password";
      img.className = "fas fa-eye-slash";
    }
  }
}
function copye(id){
  var tr = table.getElementsByTagName("tr");
  var td = tr[id].getElementsByTagName("td")[2];
  var tdimage = tr[id].getElementsByTagName("td")[4];
  if(td){
    var a = td.getElementsByTagName("div")[1];
    var p = a.getElementsByTagName("div")[0];

    var img = tdimage.getElementsByTagName("i")[1];
    img.className = "fas fa-copy";
    img.style.color = "#29bf12"
    var variable = p.innerHTML
    navigator.clipboard.writeText(variable);
    setTimeout(() => { img.className = "far fa-copy"; 
    img.style.color = "#fff"
    }, 1000);
  }
}
function copy(id) {
  var tr = table.getElementsByTagName("tr");
  var td = tr[id].getElementsByTagName("td")[2];
  var login = tr[id].getElementsByTagName("td")[1];
  var tdimage = tr[id].getElementsByTagName("td")[4];

  if (td) {
    var p = td.getElementsByTagName("input")[0];
    var img = tdimage.getElementsByTagName("i")[0];
    img.className = "fas fa-copy";
    img.style.color = "#29bf12"
    var variable = p.value;
    navigator.clipboard.writeText(variable);
    chrome.tabs.updateInput
    chrome.tabs.query({ active: true, currentWindow: true }, function ([tab]) {
      function goahead(login,password){
        var elements = document.getElementsByTagName("input"); 
        for(var i in elements){        
          var element = elements[i];  
          if(element.autocomplete != undefined && element.autocomplete.lenght != 0){ 
            if(element.autocomplete == "username"){ 
              element.click()
              element.focus();
              element.style.border = "2px solid #3A9DFC"; 
              element.style.webkitTextFillColor = "#3A9DFC"; 
              element.value = login
              setValueForElementByEvent(element);
              element.blur();
            }     
            else if(element.autocomplete.includes("password")){ 
              element.click();
              element.focus();
              element.style.border = "2px solid #3A9DFC"; 
              element.style.webkitTextFillColor = "#3A9DFC"; 
              element.value = password
              setValueForElementByEvent(element);
              element.blur();
            }   
          }
          if(element.name != undefined){
            if(element.name == "username" || element.id == "username" || element.id == "login"){ 
              element.click();
              element.focus();
              element.style.border = "2px solid #3A9DFC"; 
              element.style.webkitTextFillColor = "#3A9DFC"; 
              element.value = login
              setValueForElementByEvent(element);
              element.blur();
            }
            else if(element.name.includes("password") || element.type == "password"){
              element.click();
              element.focus();
              element.style.border = "2px solid #3A9DFC"; 
              element.style.webkitTextFillColor = "#3A9DFC"; 
              element.value = password
              setValueForElementByEvent(element);
              element.blur();
            }
          }
          if(element.type != undefined){
            if(element.type == "text" || element.type == "email"){ 
              element.click();
              element.focus();
              element.style.border = "2px solid #3A9DFC"; 
              element.style.webkitTextFillColor = "#3A9DFC"; 
              element.value = login
              setValueForElementByEvent(element);
              element.blur();
            }
            else if(element.type == "password"){
              element.click();
              element.focus();
              element.style.border = "2px solid #3A9DFC"; 
              element.style.webkitTextFillColor = "#3A9DFC"; 
              element.value = password
              setValueForElementByEvent(element);
              element.blur();
            }
          }
        } 
      }
        function setValueForElementByEvent(el) {   
          var valueToSet = el.value,
              ev1 = el.ownerDocument.createEvent('HTMLEvents'),
              ev2 = el.ownerDocument.createEvent('HTMLEvents');
          el.dispatchEvent(normalizeEvent(el, 'keydown'));
          el.dispatchEvent(normalizeEvent(el, 'keypress'));
          el.dispatchEvent(normalizeEvent(el, 'keyup'));
          ev2.initEvent('input', true, true);
          el.dispatchEvent(ev2);
          ev1.initEvent('change', true, true);
          el.dispatchEvent(ev1);
          el.blur();
          el.value !== valueToSet && (el.value = valueToSet);
        }
        function normalizeEvent(el, eventName) {
                var ev;
                if ('KeyboardEvent' in window) {
                    ev = new window.KeyboardEvent(eventName, {
                        bubbles: true,
                        cancelable: false,
                    });
                }
                else {
                    ev = el.ownerDocument.createEvent('Events');
                    ev.initEvent(eventName, true, false);
                    ev.charCode = 0;
                    ev.keyCode = 0;
                    ev.which = 0;
                    ev.srcElement = el;
                    ev.target = el;
                }
                return ev;
            }
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: goahead,
        args: [login.innerHTML,variable]
      });
    })
    setTimeout(() => {
      img.className = "far fa-copy";
      img.style.color = "#fff"
    }, 1000);
  }
}

function select(id) {
  var tr = table.getElementsByTagName("tr");
  var td = tr[id];
  if (td) {
    if (td.className == "selected") {
      td.className = "rows"
      var filterSelected = [];
      for (var ele in selectedRows) {
        var originalIndex = selectedRows[ele].originalIndex;
        if (originalIndex != id) {
          filterSelected.push(selectedRows[ele]);
        }
      }
      selectedRows = filterSelected;
    } else {
      td.className = "selected"
      var recordName = tr[id].getElementsByTagName("td")[6].innerHTML;
      var recordChangeTag = tr[id].getElementsByTagName("td")[7].innerHTML;
      if (document.getElementById("passdesc" + id)) selectedRows.push({ "originalIndex": id, "element": { "recordName": recordName, "recordChangeTag": recordChangeTag, "sharedDesc": document.getElementById("passdesc" + id).innerHTML } })
      else selectedRows.push({ "originalIndex": id, "element": { "recordName": recordName, "recordChangeTag": recordChangeTag } })
    }
  }
}
function add() {
  var modal = $("#addModal")
  modal.find('#nomeadd').val("")
  modal.find('#senhaadd').val("")
  modal.find('#usuarioadd').val("")
  strong.innerHTML = "-"
  strong.style.color = "#FFF"
  document.getElementById("advancedDice").hidden = true;
  $("#addModal").modal();
}
function buttonadicionar() {
  var modal = $("#addModal")
  if(modal.find('#nomeadd').val().length == 0){
    document.getElementById("nomeaddlabel").style.color = "#F4364C"
    return;
  }else{
    document.getElementById("nomeaddlabel").style.color = "white"
  }
  if(modal.find('#senhaadd').val().length == 0){
    document.getElementById("senhaaddlabel").style.color = "#F4364C"
    return;
  } else {
    document.getElementById("senhaaddlabel").style.color = "white"
  }
  modal.modal("hide")
  loading.style.display = "block";
  limiter.style.display = "none";
  addSenha();
}
function buttonclose(){
  search.value = ""
  var close = document.getElementById("buttonclose")
  close.style.display = "none"
  searchPass()
}
async function addSenha() {
  loadinglabel.innerHTML = chrome.i18n.getMessage("add_password") + "...";
  var xhr = new XMLHttpRequest();
  var url = host + "/iSenhasAddSenhaV4";
  if (development) url = host + "/iSenhasAddSenhaV4DEV";
  xhr.open("POST", url, true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.setRequestHeader('Access-Control-Allow-Origin', '*');
  xhr.setRequestHeader('authorization', token);

  xhr.onreadystatechange = function () {
    if (xhr.readyState === 4 && xhr.status === 200) {
      //console.log(xhr.responseText);
      limiter.style.display = "none";
      loading.style.display = "block";
      getPasswords();
    } else if (xhr.readyState === 4) {
      //console.log(xhr.responseText);
      spinner.style.display = "none";
      var language = navigator.language || navigator.userLanguage;
      loadinglabel.innerHTML = chrome.i18n.getMessage("add_password_error") + ": " + xhr.status;
    }
  };
  var modal = $("#addModal")
  let myName = modal.find("#nomeadd").val();
  if (isExtreme) {
    myName = await encryptExtreme(myName);
  }
  let observation = modal.find("#usuarioadd").val();
  if (observation.length != 0) {
    if (isExtreme) {
      observation = await encryptExtreme(observation);
    }
  }
  let description = modal.find("#descriptionadd").val();
  if (description.length != 0) {
    if (isExtreme) {
      description = await encryptExtreme(description);
    }
  }
  let myPassword = modal.find("#senhaadd").val();
  if (myPassword.length != 0) {
    if (isExtreme) {
      myPassword = await encryptExtreme(myPassword);
    }
  }
  var query = {
    element: {
      name: myName,
      observation: observation,
      description: description,
      password: myPassword,
    },
  };
  var executor = document.getElementById("vaultaddoptions");
  if(executor.selectedIndex != 0){
    var vaultid = vaults[executor.selectedIndex].recordName;
    query.element.vaultid = vaultid
  }
  xhr.send("" + JSON.stringify(query));
}
function excluir() {
  $("#excluirModal").modal();
}
function buttonremove() {
  loading.style.display = "block";
  limiter.style.display = "none";
  if (selectedRows.length == 0) {
    loadinglabel.innerHTML = chrome.i18n.getMessage("no_password_selected");
    setTimeout(() => {
      loading.style.display = "none";
      loadinglabel.style.display = "none";
      limiter.style.display = "block";
    }, 2000);
    return;
  }
  enviado = 0;
  excluirSenhas();
}
function excluirSenhas() {
  loadinglabel.innerHTML = chrome.i18n.getMessage("remove_password") + ": " + enviado;
  var xhr = new XMLHttpRequest();
  var url = host + "/iSenhasExcluirV4";
  if (development) url = host + "/iSenhasExcluirV4DEV";
  xhr.open("POST", url, true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.setRequestHeader('Access-Control-Allow-Origin', '*');
  xhr.setRequestHeader('authorization', token);

  xhr.onreadystatechange = function () {
    if (xhr.readyState === 4 && xhr.status === 200) {
      if (selectedRows.length > 200) {
        enviado = enviado + 200;
        selectedRows.splice(0, 200);
        excluirSenhas();
      } else {
        todasSenhas = [];
        selectedRows = [];
        getPasswords();
      }
    } else if (xhr.readyState === 4 && xhr.status === 401) {
      spinner.style.display = "none";
      loadinglabel.innerHTML = chrome.i18n.getMessage("remove_shared_password_error")+": " + xhr.status;
  } else if (xhr.readyState === 4) {
      //console.log(xhr.status);
      spinner.style.display = "none";
      loadinglabel.innerHTML = chrome.i18n.getMessage("remove_password_error") + ": " + xhr.status;
    }
  };
  var operations = [];
  var forvalue = 200;
  if (selectedRows.length < 200) forvalue = selectedRows.length;
  for (var z = 0; z < forvalue; z++) {
    var element = selectedRows[z].element;
    var operation = { "record": { "recordName": element.recordName, "recordChangeTag": element.recordChangeTag, "recordType": "passwords" }, "operationType": "delete" };
    if (element.sharedDesc) {
      var shared = [];
      todasSenhas.forEach(sen => {
        if (sen.recordName == element.recordName) {
          shared = sen.fields.shared.value;
        }
      });

      operation = {
        "record": {
          "recordName": element.recordName, "recordChangeTag": element.recordChangeTag, "recordType": "passwords", "fields": {
            "shared": { "value": shared }
          }
        }, "operationType": "update"
      };
    }
    operations.push(operation)
  }
  var query = { "operations": operations };
  xhr.send("{\"query\" : " + JSON.stringify(query) + "}");
}
function edit(id) {
  var password = todasSenhas[id - 1];
  if (password.fields.admin) {
    $("#shareErrorModal").modal();
  } else {
    document.getElementById("advancedDiceEdit").hidden = true;
    var modal = $("#editarModal")
    var observation = "";
    if (todasSenhas[id - 1].fields.observation != undefined) observation = todasSenhas[id - 1].fields.observation.value
    var description = "";
    if (todasSenhas[id - 1].fields.description != undefined) description = todasSenhas[id - 1].fields.description.value
    var vaultid = "0"
    var currentvaultid = ""
    if (todasSenhas[id - 1].fields.vaultid != undefined) currentvaultid = todasSenhas[id - 1].fields.vaultid.value
    for(var i=0;i<vaults.length;i++){
      let vault = vaults[i]
      let myid = vault.recordName
      let originalid = vault.originalid
      if(currentvaultid == myid || currentvaultid == originalid){
        vaultid = myid
      }
    }
    const select = document.getElementById('vaulteditoptions');
    select.value = vaultid;
    select.dispatchEvent(new Event('change'));
    if(password.fields.sharedDesc != null){
      select.disabled = true;
      document.getElementById("vaulteditlabel").style.color = "grey"
      $("#vaulteditoptions").selectpicker("refresh");
    } else {
      select.disabled = false;
      document.getElementById("vaulteditlabel").style.color = "white"
      $("#vaulteditoptions").selectpicker("refresh");
    }
    modal.find('#nomeedit').val(todasSenhas[id - 1].fields.name.value)
    modal.find('#senhaedit').val(todasSenhas[id - 1].fields.password.value)
    modal.find('#usuarioedit').val(observation)
    modal.find('#descriptionedit').val(description)
    updateInput(todasSenhas[id - 1].fields.password.value)
    let translator = chrome.i18n.getMessage("favorite_password")
    if(password.fields.sharedDesc == null){
      var favswitch = document.getElementById("favswitch")
      favswitch.hidden = false
      if(todasSenhas[id-1].fields.favorite != undefined){
        var favswitch = document.getElementById("favswitch")
        favswitch.innerHTML = `
        <img style="padding-top: 7px;padding-bottom: 7px;padding-right: 7px;height: 38px !important; width: 31px !important;" alt="Qries" src="../images/iconsmart/star.png"/>
                  <label for="recipient-name" class="col-form-label" style="color: #fff;"
                    id="favoriteditlabel">${translator}</label>
                    <label id="switchedit" class="switch" style="color: #fff;margin-left: auto;margin-right: 0px;margin-top: 8px;">
                      <input id="favoriteedit" type="checkbox" checked>
                      <span class="slider round"></span>
                  </label>
        `
      } else {
        var favswitch = document.getElementById("favswitch")
        favswitch.innerHTML = `
        <img style="padding-top: 7px;padding-bottom: 7px;padding-right: 7px;height: 38px !important; width: 31px !important;" alt="Qries" src="../images/iconsmart/star.png"/>
                  <label for="recipient-name" class="col-form-label" style="color: #fff;"
                    id="favoriteditlabel">${translator}</label>
                    <label id="switchedit" class="switch" style="color: #fff;margin-left: auto;margin-right: 0px;margin-top: 8px;">
                      <input id="favoriteedit" type="checkbox">
                      <span class="slider round"></span>
                  </label>
        `
      }
    } else {
      var favswitch = document.getElementById("favswitch")
      if(favswitch != null){
        favswitch.hidden = true
      }
    }
    editSelected = id;
    $("#editarModal").modal();
  }
}
function buttoneditar() {
  var modal = $("#editarModal")
  if(modal.find('#nomeedit').val().length == 0){
    document.getElementById("nomeeditlabel").style.color = "#F4364C"
    return;
  }else{
    document.getElementById("nomeeditlabel").style.color = "white"
  }
  if(modal.find('#senhaedit').val().length == 0){
    document.getElementById("senhaeditlabel").style.color = "#F4364C"
    return;
  } else {
    document.getElementById("senhaeditlabel").style.color = "white"
  }
  modal.modal("hide")
  loading.style.display = "block";
  loadinglabel.style.display = "block";
  limiter.style.display = "none";
  editSenha();
}
async function editSenha() {
  loadinglabel.innerHTML = chrome.i18n.getMessage("update_password") + "...";
  var xhr = new XMLHttpRequest();
  var url = host + "/iSenhasAtualizarV4";
  if (development) url = host + "/iSenhasAtualizarV4DEV";
  xhr.open("POST", url, true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.setRequestHeader('Access-Control-Allow-Origin', '*');
  xhr.setRequestHeader('authorization', token);

  xhr.onreadystatechange = function () {
    if (xhr.readyState === 4 && xhr.status === 200) {
      limiter.style.display = "none";
      loading.style.display = "block";
      getPasswords()
    } else if (xhr.readyState === 4 && xhr.status == 409) {
      spinner.style.display = "none";
      loadinglabel.innerHTML = chrome.i18n.getMessage("update_shared_password")+": " + xhr.status;
    } else if (xhr.readyState === 4) {
      //console.log(xhr.status);
      spinner.style.display = "none";
      loadinglabel.innerHTML = chrome.i18n.getMessage("update_password_error") + ": " + xhr.status;
    }
  };
  var modal = $("#editarModal")
  var myName = modal.find('#nomeedit').val()
  if(isExtreme){
    myName = await encryptExtreme(myName)
  }
  var myPassword = modal.find('#senhaedit').val()
  if(isExtreme){
    myPassword = await encryptExtreme(myPassword)
  }
  let currentPassword = todasSenhas[editSelected-1]
  var oldPassword = todasSenhas[editSelected - 1].fields.password.value;
  var observation = modal.find('#usuarioedit').val();
  var description = modal.find('#descriptionedit').val();
  var favorite = document.getElementById("favoriteedit")
  if(observation.length!=0){
    if(isExtreme){
      observation = await encryptExtreme(observation)
    }
  }
  if(description.length!=0){
    if(isExtreme){
      description = await encryptExtreme(description)
    }
  }
  if (modal.find('#senhaedit').val() == oldPassword) oldPassword = "";
  var operations = [];
  var operation = {
    "record": {
      "recordName": todasSenhas[editSelected - 1].recordName, "recordChangeTag": todasSenhas[editSelected - 1].recordChangeTag, "recordType": "passwords",
      "fields": {
        "name":{"value":myName},
        "password":{"value":myPassword},
        "observation": { "value": observation },
        "description": { "value": description }
      }
    }, "operationType": "update"
  };
  if(favorite != null && favorite.checked){
    operation.record.fields.favorite = {"value":"ok"}
  }
  if(oldPassword.length > 0){
    if(isExtreme){
      oldPassword = await encryptExtreme(oldPassword)
    }
    operation.record.fields.old = {"value":oldPassword}
  }
  if(currentPassword.fields.secret != null){
    if(isExtreme){
      currentPassword.fields.secret.value = await encryptExtreme(currentPassword.fields.secret.value)
    }
    operation.record.fields.secret = {"value":currentPassword.fields.secret.value}
  }
  if(currentPassword.fields.algorithm != null){
    if(isExtreme){
      currentPassword.fields.algorithm.value = await encryptExtreme(currentPassword.fields.algorithm.value)
    }
    operation.record.fields.algorithm = {"value":currentPassword.fields.algorithm.value}
  }
  if(currentPassword.fields.period != null){
    if(isExtreme){
      currentPassword.fields.period.value = await encryptExtreme(currentPassword.fields.period.value)
    }
    operation.record.fields.period = {"value":currentPassword.fields.period.value}
  }
  if(currentPassword.fields.digits != null){
    if(isExtreme){
      currentPassword.fields.digits.value = await encryptExtreme(currentPassword.fields.digits.value)
    }
    operation.record.fields.digits = {"value":currentPassword.fields.digits.value}
  }
  var executor = document.getElementById("vaulteditoptions");
  if(executor.selectedIndex != 0){
    var vaultid = vaults[executor.selectedIndex].recordName;
    operation.record.fields.vaultid = {"value":vaultid}
  }
  if(todasSenhas[editSelected-1].fields.shared){
    var enc = [];
    todasSenhas[editSelected-1].fields.shared.value.forEach(element => {
      enc.push(element);
    });
    operation.record.fields.shared = {"value":enc}
  }
  operations.push(operation)
  var query = { "operations": operations };
  xhr.send("{\"query\" : " + JSON.stringify(query) + "}");
}
function gerarsenha() {
  document.getElementById("advancedDice").hidden = false;
  var modaledit = $("#editarModal")
  var newPass = Password.generate(slider.value,maiusculas.checked,minusculas.checked,numeros.checked,caracteres.checked);
  //console.log(newPass)
  var modal = $("#addModal")
  modal.find('#senhaadd').val(newPass)
  updateInput(newPass)
}
function gerarsenhaedit() {
  document.getElementById("advancedDiceEdit").hidden = false;
  var modaledit = $("#editarModal")
  var newPass = Password.generate(sliderEdit.value,maiusculasEdit.checked,minusculasEdit.checked,numerosEdit.checked,caracteresEdit.checked);
  //console.log(newPass)
  modaledit.find('#senhaedit').val(newPass)
  updateInput(newPass)
}
var Password = {

  _pattern: /[a-zA-Z0-9_\-\+\.]/,


  _getRandomByte: function () {
    // http://caniuse.com/#feat=getrandomvalues
    if (window.crypto && window.crypto.getRandomValues) {
      var result = new Uint8Array(1);
      window.crypto.getRandomValues(result);
      return result[0];
    }
    else if (window.msCrypto && window.msCrypto.getRandomValues) {
      var result = new Uint8Array(1);
      window.msCrypto.getRandomValues(result);
      return result[0];
    }
    else {
      return Math.floor(Math.random() * 256);
    }
  },

  generate: function (length,mai,min,num,carac) {
    return Array.apply(null, { 'length': length })
      .map(function () {
        var result;
        var pat = "[";
        if(mai)pat = pat+"A-Z"
        if(min)pat = pat+"a-z"
        if(num)pat = pat+"0-9"
        if(carac)pat = pat+"_\\-\\+\\."
        pat = pat +"]"
        var pattern = new RegExp(pat,"g")
        if(pat != "[]"){
          while (true) {
            result = String.fromCharCode(this._getRandomByte());
            if (pattern.test(result)) {
              return result;
            }
          }
        } else {
          return "";
        }
      }, this)
      .join('');
  }

};

function updateInput(ish) {
  var sizeOfCharacterSet = 0;
  if (ish.match(/[a-z]+/)) {
    sizeOfCharacterSet += 26;
  }
  if (ish.match(/[A-Z]+/)) {
    sizeOfCharacterSet += 26;
  }
  if (ish.match(/[0-9]+/)) {
    sizeOfCharacterSet += 26;
  }
  if (ish.match(/[_-{}()|'".:;,<>?!@#%]+/)) {
    sizeOfCharacterSet += 20;
  }
  if (ish.match(/[$=+/€®ŧ←↓→øþæßðđŋħjĸł»©“”nµ]+/)) {
    sizeOfCharacterSet += 10;
  }
  if (ish.match(/[ ]+/)) {
    sizeOfCharacterSet += 1;
  }
  var entropy = Math.log2(sizeOfCharacterSet);
  var entropy = entropy * ish.length;
  if (entropy < 28) {
    strong.innerHTML = chrome.i18n.getMessage("very_weak")
    strong.style.color = "#F4364C"
    strongedit.innerHTML = chrome.i18n.getMessage("very_weak")
    strongedit.style.color = "#F4364C"
  } else if (entropy < 36) {
    strong.innerHTML = chrome.i18n.getMessage("weak")
    strong.style.color = "#F4364C"
    strongedit.innerHTML = chrome.i18n.getMessage("weak")
    strongedit.style.color = "#F4364C"
  } else if (entropy < 60) {
    strong.innerHTML = chrome.i18n.getMessage("regular")
    strong.style.color = "#F5BB00"
    strongedit.innerHTML = chrome.i18n.getMessage("regular")
    strongedit.style.color = "#F5BB00"
  } else if (entropy < 128) {
    strong.innerHTML = chrome.i18n.getMessage("strong")
    strong.style.color = "#29bf12"
    strongedit.innerHTML = chrome.i18n.getMessage("strong")
    strongedit.style.color = "#29bf12"
  } else {
    strong.innerHTML = chrome.i18n.getMessage("very_strong")
    strong.style.color = "#29bf12"
    strongedit.innerHTML = chrome.i18n.getMessage("very_strong")
    strongedit.style.color = "#29bf12"
  }
}
function getListIconFromText(text){
  throw new Error("Proprietary module")
}