/*
 * detectOAuth2Vul -- called on an OAuth 2.0 object
 * returns the vulnerabilities that we can identify from the OAuth 2.0 requests
 * @param {OAuth 2.0 Object} AN OAuth 2.0 Object defined in func dtectOAuht2
 * @return {Vulnerability Object} returns an object that contains the vulnerabilities. from the description.md file
 *
 */

function detectOAuth2Vul(oauth2request, oauth2response) {
    var OAuth2Vul = {
        CSRF:null,
        IDLogin: null,
        redirectURIMismatch:null,
        flowMisuse: null,
        clientSecretLeak: null,
        accessTokenLeak: null,
        codeLeak: null,
        idTokenLeak:null,
        RP:null,
        IdP:null,
        isVul:null
    }
    var request = oauth2request;
    var response = oauth2response;


    OAuth2Vul.RP = request.RPDomain;
    OAuth2Vul.IdP = request.IdP;
    if (request.redirectURI === "postmessage"){
        console.log("Dealing with Postmessage API OAuth2 messages!!" + OAuth2Vul.RP + " --- " + OAuth2Vul.IdP);
        if (response.method === "POST"){
            if (response.formData){
                // console.log("dealing with Google postmessage API with formData!")
                // console.log(response.formData);
                var formData = response.formData;
                var keys = Object.keys(formData);

                /// dealing with facebook signed request.
                if (response.IdP === "https://www.facebook.com"){
                    var headers = response.requestHeaders;
                    for (var i = 0; i < headers.length; i++) {
                        var header = headers[i];
                        if (header.name.toLowerCase() === "cookie"){
                            var cookies = extractCookie(header["value"]);
                            for (var key in cookies){
                                if (isFacebookSignedRequest(cookies[key])){
                                    console.log("This is a response containing a Facebook signed request");
                                    // return OAuth2Vul;
                                    console.log(response);
                                }
                            }
                        }
                    }
                }

                var counterCSRF = false;
                for (var i = 0; i < keys.length; i++) {
                    var data = formData[keys[i]][0];
                    if (keys[i].search(/csrf/i) >=0 || keys[i].search(/xsrf/i)>= 0 || keys[i].search(/session/i) >=0){
                        if (data.length > 5 && isNaN(data)){
                            counterCSRF = true;
                        }
                    }
                    if (isGoogleAccessToken(data)){
                        OAuth2Vul.flowMisuse = true;
                        OAuth2Vul.isVul = true;
                        if (response.RPProtocol === "http:"){
                            OAuth2Vul.accessTokenLeak = true;
                        }
                    }
                    if (isGoogleIDToken(data)){
                        OAuth2Vul.flowMisuse = true;
                        if (response.RPProtocol === "http:"){
                            OAuth2Vul.idTokenLeak = true;
                            OAuth2Vul.isVul = true;
                        }
                    }
                    if (isGoogleCode(data)){
                        if (response.RPProtocol === "http:"){
                            OAuth2Vul.codeLeak = true;
                            OAuth2Vul.isVul = true;
                        }
                    }
                    if (keys[i].indexOf("client_secret") >= 0){
                        OAuth2Vul.clientSecretLeak = true;
                        OAuth2Vul.isVul = true;
                    }
                    if (isFacebookAccessToken(data)) {
                        OAuth2Vul.flowMisuse = true;
                        OAuth2Vul.isVul = true;
                        if (response.RPProtocol === "http:"){
                            OAuth2Vul.accessTokenLeak = true;
                        }
                    }
                }
                if (!counterCSRF){
                    OAuth2Vul.CSRF = true;
                    OAuth2Vul.isVul = true;
                }
                // console.log(OAuth2Vul);
                return OAuth2Vul;
            }else if (response.JSONData){
                // console.log("dealing with Google postmessage API with JSONData!")
                // console.log(response.JSONData);
                if (response.IdP === "https://www.facebook.com"){
                    var headers = response.requestHeaders;
                    for (var i = 0; i < headers.length; i++) {
                        var header = headers[i];
                        if (header.name.toLowerCase() === "cookie"){
                            var cookies = extractCookie(header["value"]);
                            for (var key in cookies){
                                if (isFacebookSignedRequest(cookies[key])){
                                    console.log("This is a response containing a Facebook signed request");
                                    console.log(response);
                                    // return OAuth2Vul;
                                }
                            }
                        }
                    }
                }
                var data = JSON.stringify(response.JSONData);
                if (isGoogleAccessToken(data)){
                    OAuth2Vul.flowMisuse = true;
                    OAuth2Vul.isVul = true;
                    if (response.RPProtocol === "http:"){
                        OAuth2Vul.accessTokenLeak = true;
                    }
                }
                if (isGoogleIDToken(data)){
                    OAuth2Vul.flowMisuse = true;
                    if (response.RPProtocol === "http:"){
                        OAuth2Vul.idTokenLeak = true;
                        OAuth2Vul.isVul = true;
                    }
                }
                if (isGoogleCode(data)){
                    if (response.RPProtocol === "http:"){
                        OAuth2Vul.codeLeak = true;
                        OAuth2Vul.isVul = true;
                    }
                }
                if(isFacebookAccessToken(data)){
                    OAuth2Vul.flowMisuse = true;
                    OAuth2Vul.isVul = true;
                    if (response.RPProtocol === "http:"){
                        OAuth2Vul.accessTokenLeak = true;
                    }
                }
                // console.log(OAuth2Vul);
                return OAuth2Vul;
            }

        }else{
            //  Postmessage API using get to send back response.
            //
            console.log("dealing with Possmessage API using GET method!!!")

            if (response.state && response.state.length > 5 && isNaN(response.state)){
                OAuth2Vul.CSRF = false;
            }else{
                OAuth2Vul.CSRF = true;
                OAuth2Vul.isVul = true;
            }
            if (response.code && response.RPProtocol === "http:"){
                OAuth2Vul.codeLeak = true;
                OAuth2Vul.isVul = true;
            }
            if (response.accessToken) {
                OAuth2Vul.flowMisuse = true;
                OAuth2Vul.isVul = true;
                console.log("An access token instead of a code is submitted back!!!")
                if (response.RPProtocol === "http:"){
                    OAuth2Vul.accessTokenLeak = true;
                }
            }

            if (response.IdP === "https://www.facebook.com"){
                var headers = response.requestHeaders;
                for (var i = 0; i < headers.length; i++) {
                    var header = headers[i];
                    if (header.name.toLowerCase() === "cookie"){
                        var cookies = extractCookie(header["value"]);
                        for (var key in cookies){
                            if (isFacebookSignedRequest(cookies[key])){
                                console.log("This is a response containing a Facebook signed request");
                                console.log(response);
                                // return OAuth2Vul;
                            }
                        }
                    }
                }
            }
            // console.log(OAuth2Vul);
            return OAuth2Vul;
        }

    }else{
        // normal OAuth 2.0 request and response
        // dealing with post method.
        if (response.method === "POST"){
            console.log("Dealing with a normal OAuth 2.0 POST ! " + request.RPDomain + " --- " + request.IdP);
            if (response.formData){
                // console.log("dealing with Google postmessage API with formData!")
                // console.log(response.formData);
                var formData = response.formData;
                var keys = Object.keys(formData);
                /// dealing with facebook signed request.

                if (response.IdP === "https://www.facebook.com"){
                    var headers = response.requestHeaders;
                    for (var i = 0; i < headers.length; i++) {
                        var header = headers[i];
                        if (header.name.toLowerCase() === "cookie"){
                            var cookies = extractCookie(header["value"]);
                            for (var key in cookies){
                                if (isFacebookSignedRequest(cookies[key])){
                                    console.log("This is a response containing a Facebook signed request");
                                    console.log(response);
                                    // return OAuth2Vul;
                                }
                            }
                        }
                    }
                }

                for (var i = 0; i < keys.length; i++) {
                    var data = formData[keys[i]][0];
                    if (isGoogleAccessToken(data)){
                        OAuth2Vul.flowMisuse = true;
                        OAuth2Vul.isVul = true;
                        if (response.RPProtocol === "http:"){
                            OAuth2Vul.accessTokenLeak = true;
                        }
                    }
                    if (isGoogleIDToken(data)){
                        OAuth2Vul.flowMisuse = true;
                        if (response.RPProtocol === "http:"){
                            OAuth2Vul.idTokenLeak = true;
                            OAuth2Vul.isVul = true;
                        }
                    }
                    if (isGoogleCode(data)){
                        if (response.RPProtocol === "http:"){
                            OAuth2Vul.codeLeak = true;
                            OAuth2Vul.isVul = true;
                        }
                    }
                    if (keys[i].indexOf("client_secret") >= 0){
                        OAuth2Vul.clientSecretLeak = true;
                        OAuth2Vul.isVul = true;
                    }
                    if (isFacebookAccessToken(data)) {
                        OAuth2Vul.flowMisuse = true;
                        OAuth2Vul.isVul = true;
                        if (response.RPProtocol === "http:"){
                            OAuth2Vul.accessTokenLeak = true;
                        }
                    }
                    if (isFacebookCode(data)){
                        if (response.RPProtocol === "http:"){
                            OAuth2Vul.codeLeak = true;
                            OAuth2Vul.isVul = true;
                        }
                    }

                }
                // console.log(OAuth2Vul);
                return OAuth2Vul;
            }else if (response.JSONData){
                // console.log("dealing with Google postmessage API with JSONData!")
                // console.log(response.JSONData);
                var data = JSON.stringify(response.JSONData);
                if (response.IdP === "https://www.facebook.com"){
                    var headers = response.requestHeaders;
                    for (var i = 0; i < headers.length; i++) {
                        var header = headers[i];
                        if (header.name.toLowerCase() === "cookie"){
                            var cookies = extractCookie(header["value"]);
                            for (var key in cookies){
                                if (isFacebookSignedRequest(cookies[key])){
                                    console.log("This is a response containing a Facebook signed request");
                                    console.log(response);
                                    // return OAuth2Vul;
                                }
                            }
                        }
                    }
                }
                if (isGoogleAccessToken(data)){
                    OAuth2Vul.flowMisuse = true;
                    OAuth2Vul.isVul = true;
                    if (response.RPProtocol === "http:"){
                        OAuth2Vul.accessTokenLeak = true;
                    }
                }
                if (isGoogleIDToken(data)){
                    OAuth2Vul.flowMisuse = true;
                    if (response.RPProtocol === "http:"){
                        OAuth2Vul.idTokenLeak = true;
                        OAuth2Vul.isVul = true;
                    }
                }
                if (isGoogleCode(data)){
                    if (response.RPProtocol === "http:"){
                        OAuth2Vul.codeLeak = true;
                        OAuth2Vul.isVul = true;
                    }
                }
                if(isFacebookAccessToken(data)){
                    OAuth2Vul.flowMisuse = true;
                    OAuth2Vul.isVul = true;
                    if (response.RPProtocol === "http:"){
                        OAuth2Vul.accessTokenLeak = true;
                    }
                }
                // console.log(OAuth2Vul);
                return OAuth2Vul;
            }
        }else{
            console.log("Dealing with a normal OAuth 2.0 Get ! " + request.RPDomain + " --- " + request.IdP);

            // deal with Facebook signed request.
            if (response.IdP === "https://www.facebook.com"){
                var headers = response.requestHeaders;
                for (var i = 0; i < headers.length; i++) {
                    var header = headers[i];
                    if (header.name.toLowerCase() === "cookie"){
                        var cookies = extractCookie(header["value"]);
                        for (var key in cookies){
                            if (isFacebookSignedRequest(cookies[key])){
                                console.log("This is a response containing a Facebook signed request");
                                console.log(response);
                                // return OAuth2Vul;
                            }
                        }
                    }
                }
            }
            // deal with normal request.
            if (request.state && request.state.length > 5 && isNaN(request.state) && (response.state === request.state)){
                OAuth2Vul.CSRF = false;
            }else{
                OAuth2Vul.CSRF = true;
                OAuth2Vul.isVul = true;
            }
            if (response.code && response.RPProtocol === "http"){
                OAuth2Vul.codeLeak = true;
                OAuth2Vul.isVul = true;
            }else{
                OAuth2Vul.codeLeak = false;
            }
            // console.log(OAuth2Vul);
            return OAuth2Vul;
        }
    }
}



/*
 * readOAuthRequestFromLocalStorage
 * returns the OAuth 2.0 requests that we collected
 *
 * @return {Request Object} returns an object that contains the vulnerabilities. from the description.md file
 *
 */

function readOAuthRequestFromLocalStorage(){
    var urls = Object.keys(localStorage);
    // console.log(urls);

    for (var i = 0; i < urls.length; i++) {
        if(urls[i].indexOf(":") < 0){
            var requests = JSON.parse(localStorage.getItem(urls[i]));
            var responses = JSON.parse(localStorage.getItem(urls[i]+":response"));
            // console.log(responses);

            var h = document.createElement("H1");
            h.setAttribute("id", requests[0].RPDomain);
            var t = document.createTextNode("OAuth2.0 Vulnerability test report for RP: " + requests[0].RPDomain);     // Create a text node
            h.appendChild(t);
            document.body.appendChild(h);

            var removeHeader = true;

            for (var j = 0; j < requests.length; j++) {
                for (var k = 0; k < responses.length; k++) {
                    if (responses[k].IdP === requests[j].IdP){
                        var request = requests[j];
                        var response = responses[k];
                        // console.log(response);
                        var vuls = detectOAuth2Vul(request, response);
                        if (vuls.isVul){
                            // create tables to report the detected vulnerabilities!!!
                            var table = document.createElement("TABLE");
                            table.setAttribute("id", requests[j].RPDomain+requests[j].IdP);
                            var header = document.createElement("TH");
                            header.setAttribute("colspan", 2);
                            var txt = document.createTextNode("IdP: " + requests[j].IdP)
                            header.appendChild(txt);
                            table.appendChild(header);
                            document.body.appendChild(table);

                            if (vuls.CSRF){
                                console.log(response);
                                insertToTable(requests[j].RPDomain+requests[j].IdP, "CSRF", "A possible CSRF attack exists in the OAuth 2.0 Communications between RP: " + vuls.RP + " --- IdP: " + vuls.IdP);
                            }
                            if (vuls.flowMisuse){
                                if (vuls.IdP === "https://accounts.google.com"){
                                    insertToTable(requests[j].RPDomain+requests[j].IdP, "OpenID Connect Flow Misuse", "OpenID Connect Authorization Flows!! only code instead of a combination of an access_token, code or id_token should be submit back to the RP's Authentication Endpoint!")
                                }else if (vuls.IdP === "https://www.facebook.com"){
                                   insertToTable(requests[j].RPDomain+requests[j].IdP, "OAuth 2.0 Flow Misuse", "OAuth 2.0 Authorization Flows!! only code instead of an access_token should be submit back to the RP's Authentication Endpoint!")
                                }
                            }
                            if (vuls.clientSecretLeak){
                                insertToTable(requests[j].RPDomain+requests[j].IdP, "RP's OAuth2.0 client_secret leak", "The IdP: " + vuls.IdP + "issued client_secret is leaked to a third party!!");
                            }
                            if(vuls.idTokenLeak){
                                insertToTable(requests[j].RPDomain+requests[j].IdP, "OpenID Connect id_token leak", "An id_token is transferred without any protection to the RP: " + vuls.RP + " !!!");
                            }
                            if(vuls.accessTokenLeak){
                                insertToTable(requests[j].RPDomain+requests[j].IdP, "access_token leak", "An access_token is transferred without any protection to the RP: " + vuls.RP + " !!!");
                            }
                            if(vuls.codeLeak){
                                insertToTable(requests[j].RPDomain+requests[j].IdP, "code leak", "A code is transferred without any protection to the RP: " + vuls.RP + " !!!");
                            }
                            if(vuls.IDLogin){
                                if (vuls.IdP === "https://accounts.google.com"){
                                    insertToTable(requests[j].RPDomain+requests[j].IdP, "ID Login", "An attacker can use the victim user's google ID login to : " + vuls.RP);
                                }else if (vuls.IdP === "https://www.facebook.com"){
                                   insertToTable(requests[j].RPDomain+requests[j].IdP, "ID Login", "An attacker can use the victim user's Facebook ID login to : " + vuls.RP);
                                }
                            }
                            removeHeader = false;
                        }else{
                            console.log("No threats detected Between RP: " + requests[j].RPDomain + " and IdP: " + requests[j].IdP);
                        }
                    }
                }
            }
            if (removeHeader) {
                var h1 = document.getElementById(requests[0].RPDomain);
                if (h1) {
                    h1.parentNode.removeChild(h1);
                }
            }
        }
    }
}

/*
 * readOAuthRequestFromLocalStorage
 * returns the OAuth 2.0 requests that we collected
 *
 * @return {Request Object} returns an object that contains the vulnerabilities. from the description.md file
 *
 */

function readOAuthRequestFromJSON(){
    var xhr = new XMLHttpRequest;
    xhr.open("GET", chrome.runtime.getURL("contents/data.json"));
    xhr.onreadystatechange = function() {
        if (this.readyState == 4) {
            console.log("request finished, now parsing");
            parsed_json = JSON.parse(xhr.responseText);
            var urls = Object.keys(parsed_json);
            for (var i = 0; i < urls.length; i++) {
                if(urls[i].indexOf(":response") < 0){
                    var requests = parsed_json[urls[i]]
                    var responses = parsed_json[urls[i]+":response"];
                    // console.log(responses);
                    var h = document.createElement("H1");
                    h.setAttribute("id", requests[0].RPDomain);
                    var t = document.createTextNode("OAuth2.0 Vulnerability test report for RP: " + requests[0].RPDomain);     // Create a text node
                    h.appendChild(t);
                    document.body.appendChild(h);
                    var removeHeader = true;
                    for (var j = 0; j < requests.length; j++) {
                        for (var k = 0; k < responses.length; k++) {
                            if (responses[k].IdP === requests[j].IdP){
                                var request = requests[j];
                                var response = responses[k];
                                // console.log(response);
                                var vuls = detectOAuth2Vul(request, response);
                                if (vuls.isVul){
                                    // create tables to report the detected vulnerabilities!!!
                                    var table = document.createElement("TABLE");
                                    table.setAttribute("id", requests[j].RPDomain+requests[j].IdP);
                                    var header = document.createElement("TH");
                                    header.setAttribute("colspan", 2);
                                    var txt = document.createTextNode("IdP: " + requests[j].IdP)
                                    header.appendChild(txt);
                                    table.appendChild(header);
                                    document.body.appendChild(table);

                                    if (vuls.CSRF){
                                        console.log(response);
                                        insertToTable(requests[j].RPDomain+requests[j].IdP, "CSRF", "A possible CSRF attack exists in the OAuth 2.0 Communications between RP: " + vuls.RP + " --- IdP: " + vuls.IdP);
                                    }
                                    if (vuls.flowMisuse){
                                        if (vuls.IdP === "https://accounts.google.com"){
                                            insertToTable(requests[j].RPDomain+requests[j].IdP, "OpenID Connect Flow Misuse", "OpenID Connect Authorization Flows!! only code instead of a combination of an access_token, code or id_token should be submit back to the RP's Authentication Endpoint!")
                                        }else if (vuls.IdP === "https://www.facebook.com"){
                                           insertToTable(requests[j].RPDomain+requests[j].IdP, "OAuth 2.0 Flow Misuse", "OAuth 2.0 Authorization Flows!! only code instead of an access_token should be submit back to the RP's Authentication Endpoint!")
                                        }
                                    }
                                    if (vuls.clientSecretLeak){
                                        insertToTable(requests[j].RPDomain+requests[j].IdP, "RP's OAuth2.0 client_secret leak", "The IdP: " + vuls.IdP + "issued client_secret is leaked to a third party!!");
                                    }
                                    if(vuls.idTokenLeak){
                                        insertToTable(requests[j].RPDomain+requests[j].IdP, "OpenID Connect id_token leak", "An id_token is transferred without any protection to the RP: " + vuls.RP + " !!!");
                                    }
                                    if(vuls.accessTokenLeak){
                                        insertToTable(requests[j].RPDomain+requests[j].IdP, "access_token leak", "An access_token is transferred without any protection to the RP: " + vuls.RP + " !!!");
                                    }
                                    if(vuls.codeLeak){
                                        insertToTable(requests[j].RPDomain+requests[j].IdP, "code leak", "A code is transferred without any protection to the RP: " + vuls.RP + " !!!");
                                    }
                                    if(vuls.IDLogin){
                                        if (vuls.IdP === "https://accounts.google.com"){
                                            insertToTable(requests[j].RPDomain+requests[j].IdP, "ID Login", "An attacker can use the victim user's google ID login to : " + vuls.RP);
                                        }else if (vuls.IdP === "https://www.facebook.com"){
                                           insertToTable(requests[j].RPDomain+requests[j].IdP, "ID Login", "An attacker can use the victim user's Facebook ID login to : " + vuls.RP);
                                        }
                                    }
                                    removeHeader = false;
                                }else{
                                    console.log("No threats detected Between RP: " + requests[j].RPDomain + " and IdP: " + requests[j].IdP);
                                }
                            }
                        }
                    }
                    if (removeHeader) {
                        var h1 = document.getElementById(requests[0].RPDomain);
                        if (h1) {
                            h1.parentNode.removeChild(h1);
                        }
                    }
                }
            }
        }
    };
    xhr.send();
    // console.log(urls);
}


/*
 * insert a row into a table
 */

function insertToTable(RPDomain, vul, description) {
    var table = document.getElementById(RPDomain);
    var row = table.insertRow(-1);
    var cell1 = row.insertCell(0);
    var cell2 = row.insertCell(1);
    // Add some text to the new cells:
    cell1.innerHTML = vul;
    cell2.innerHTML = description;
    // body...
}


// readOAuthRequestFromLocalStorage();
readOAuthRequestFromJSON();
/*
 * check whether a string is URL.
 */

function isURL(str) {
  var pattern = new RegExp('^(https?:\\/\\/)?'+ // protocol
  '((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.?)+[a-z]{2,}|'+ // domain name
  '((\\d{1,3}\\.){3}\\d{1,3}))'+ // OR ip (v4) address
  '(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*'+ // port and path
  '(\\?[;&a-z\\d%_.~+=-]*)?'+ // query string
  '(\\#[-a-z\\d_]*)?$','i'); // fragment locator
  return pattern.test(str);
}

/*
 * check a string is a code.
 */

function isGoogleCode(str) {
    var uri_dec;
    try {
        uri_dec = decodeURIComponent(str);
        // console.log(formData);
    }catch(err){
        uri_dec = str;
    }
    var pattern = new RegExp('4\\/.{43}');
    return pattern.test(uri_dec);
}

/*
 * check a string is an ID token.
 */

function isGoogleIDToken(str) {
  var uri_dec;
  try {
      uri_dec = decodeURIComponent(str);
      // console.log(formData);
  }catch(err){
      uri_dec = str;
  }
  var pattern = new RegExp('eyJ.*\\.eyJ.*\\..*');
  return pattern.test(uri_dec);
}

/*
 * check a string is an access token.
 */

function isGoogleAccessToken(str) {
    var uri_dec;
    try {
        uri_dec = decodeURIComponent(str);
        // console.log(formData);
    }catch(err){
        uri_dec = str;
    }
    var pattern = new RegExp('ya29\\..*');
    return pattern.test(uri_dec);
}

/*
 * check a string is an access token.
 */

function isFacebookCode(str) {
    var uri_dec;
    try {
        uri_dec = decodeURIComponent(str);
        // console.log(formData);
    }catch(err){
        uri_dec = str;
    }
    var pattern = new RegExp('AQ.{342}');
    return pattern.test(uri_dec);
}


/*
 * check a string is an access token.
 */

function isFacebookAccessToken(str) {
    var uri_dec;
    try {
        uri_dec = decodeURIComponent(str);
        // console.log(formData);
    }catch(err){
        uri_dec = str;
    }
    var pattern = new RegExp('EAA.*ZD');
    return pattern.test(uri_dec);
}

/*
 * check a string is facEbook ID.
 */

function isFacebookID(str) {
    var uri_dec;
    try {
        uri_dec = decodeURIComponent(str);
        // console.log(formData);
    }catch(err){
        uri_dec = str;
    }
    var pattern = new RegExp('^[0-9]{15}$');
    var pattern1 = new RegExp('^[0-9]{16}$');
    return pattern.test(uri_dec) || pattern1.test(uri_dec);
}


/*
 * extract value from the cookie headers
 */

function extractCookie(cookie){
    var values = cookie.split(";");
    var cookies = {};
    for (var i = 0; i < values.length; i++) {
        var n = values[i].indexOf("=");
        var name = values[i].substring(0,n);

        var value = values[i].substring(n+1);
        cookies[name] = value;
    }
    return cookies;
}


/*
 * check a string is SignedRequest.
 */

function isFacebookSignedRequest(str){
    var uri_dec;
    try {
        uri_dec = decodeURIComponent(str);
        // console.log(formData);
    }catch(err){
        uri_dec = str;
    }

    var pattern = new RegExp('.{43}\\.eyJ.*');
    return pattern.test(str) ;
}

