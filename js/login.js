var token = "";

window.onload = function () {
    translate()
    loading.style.display = "none";
    token = makeid(30);
    const qrcode = document.getElementById("qrcode");
    const qrdiv = document.getElementById("qrdiv");
    var QR_CODE = new QRCode("qrcode", {
        width: 200,
        height: 200,
        colorDark: "#090909",
        colorLight: "#FFFFFF",
        correctLevel: QRCode.CorrectLevel.H,
    });
    QR_CODE.clear();
    QR_CODE.makeCode(token);
    qrdiv.className = "qrdiv";
};
function makeid(length) {
    var result = '';
    var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var charactersLength = characters.length;
    for (var i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() *
            charactersLength));
    }
    return result;
}
function login(){
    loading.style.display = "block";
    loginform.style.display = "none";
}
$("#btn_login").click(function(){
    authenticate(0)
});

function authenticate(count){
    loading.style.display = "block";
    loginform.style.display = "none";
    var xhr = new XMLHttpRequest();
    var url = host+"/iSenhasLoginV4";
    if(development) url = host+"/iSenhasLoginV4DEV";
    xhr.open("POST", url, true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.setRequestHeader('Access-Control-Allow-Origin', '*');
    xhr.setRequestHeader('authorization', token);
    xhr.onreadystatechange = async function () {
        if (xhr.readyState === 4 && xhr.status === 200) {
            var objResponse = JSON.parse(xhr.responseText);
            const d = new Date();
            var time = 168;
            var mytime = d.setTime(d.getTime() + (time*60*60*1000));
            chrome.cookies.set({
                url: "https://isenhas.com.br",
                name: "tokenis",
                value: objResponse.token,
                secure: true,
                httpOnly: true,
                sameSite: "strict",
                expirationDate: mytime
              }, function (cookie) {
                if(objResponse.extremeprivacy != null){
                    chrome.cookies.set({
                        url: "https://isenhas.com.br",
                        name: "recovery",
                        value: "wait",
                        secure: true,
                        httpOnly: true,
                        sameSite: "strict",
                        expirationDate: mytime
                    },async function (cookie3){
                        await importAndStoreKey(objResponse.sha)
                        window.location = 'recoverykey.html';
                    });
                } else {
                    chrome.cookies.set({
                        url: "https://isenhas.com.br",
                        name: "recovery",
                        value: "none",
                        secure: true,
                        httpOnly: true,
                        sameSite: "strict",
                        expirationDate: mytime
                    },async function (cookie3){
                        await importAndStoreKey(objResponse.sha)
                        window.location = 'senhas.html';
                    });
                }
            });
        } else if (xhr.readyState === 4 && xhr.status === 201) {
            count++
            if(count<21){
                loadinglabel.innerHTML = chrome.i18n.getMessage("authenticatingUser")+" ("+count+")";
                setTimeout(() => {
                    authenticate(count)
                }, 3000);
            } else {
                spinner.style.display = "none";
                loadinglabel.innerHTML = chrome.i18n.getMessage("code_notfound");
            }
        } else if(xhr.readyState === 4){
            console.log(xhr.responseText)
            spinner.style.display = "none";
            loadinglabel.innerHTML = chrome.i18n.getMessage("login_error")+": "+xhr.status;
        }
    };
    xhr.send();
}
function translate(){
    document.getElementById("desc1").innerHTML = chrome.i18n.getMessage("loginDesc1");
    document.getElementById("desc2").innerHTML = chrome.i18n.getMessage("loginDesc2");
    document.getElementById("btn_login").innerHTML = chrome.i18n.getMessage("signIn");
    document.getElementById("loadinglabel").innerHTML = chrome.i18n.getMessage("authenticatingUser");
    document.getElementById("title_name").innerHTML = chrome.i18n.getMessage("isenhas_title");
}