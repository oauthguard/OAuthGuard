console.log("Hello, World!");


const googleOAuth2RegsObject = {
    'google.com': {
        access_token: new RegExp('(ya29\..{124,127})'),
        code: new RegExp('(?:code=)(4/.{43,86})(?:&?)|(?:code=)(4%2F.{43,86})(?:&?)|(?:[cC]ode": ?")(4/.{43,86})(?:&?)|(?:[cC]ode": ?")(4%2F.{43,86})(?:&?)|(?:otc=)(4%2F.{43,86})(?:&?)|(?:otc=)(4/.{43,86})(?:&?)'),
        id_token: /(eyJhbGciOiJSUzI1NiIsImtpZCI6.*\.eyJ.*\..{342})/
    }
};

// set up https-upgrade options
var httpsOption = localStorage.getItem("https-options");
if (!httpsOption) {
    localStorage.setItem("https-options", 0);
}


// read user defined regular expressions
const customizedRegsObjects = JSON.parse(localStorage.getItem('re_expressions'));

chrome.webRequest.onBeforeRequest.addListener(
    function (details) {
        // This used to extract headers for post message.
        if (details.method === 'POST') {
            // this oauth2Response referer attribute is ''; cause requestHeaders
            // is null in onBeforeRequest event.
            var requestId = details.requestId;
            var oauth2Response = detectOAuth2Response(details);
            if (oauth2Response) {
                chrome.webRequest.onBeforeSendHeaders.addListener(
                    function (dets) {
                        var detReuqestId = dets.requestId;
                        var blocking = false;
                        if (dets.method === "POST" && requestId === detReuqestId) {
                            // console.log("This is a request for the POST rquest with requestId " + requestId);
                            var headers = dets.requestHeaders;
                            // console.log(headers);
                            var referer = "";
                            var cookie = "";
                            for (var i = 0; i < headers.length; i++) {
                                var header = headers[i];
                                if (header.name.toLowerCase() === "cookie") {
                                    cookie = header["value"];
                                } else if (header.name.toLowerCase() === "referer") {
                                    referer = header["value"];
                                }
                            }
                            oauth2Response.cookie = cookie;
                            oauth2Response.referer = referer;
                            console.log(oauth2Response);
                            storeOAuth2Response(oauth2Response);
                            var oauth2Request = localStorage.getItem(oauth2Response.RPDomain);
                            if (oauth2Request) {
                                oauth2Request = JSON.parse(oauth2Request).request;
                                var threats = detectOAuth2Threats(oauth2Request, oauth2Response);
                                // print threats to console
                                printThreats(threats);
                                if (threats.thirdPartyTokenLeaks) {
                                    blocking = true;
                                    // store counter into local storage
                                    storeCounter('thirdPartyTokenLeaks');
                                }
                                if (threats.CSRFAttack) {
                                    blocking = true;
                                    // store counter into local storage
                                    storeCounter("CSRF");
                                }
                            } else {
                                var threats = detectOAuth2Threats(null, oauth2Response);
                                // print threats to console
                                printThreats(threats);
                                if (threats.thirdPartyTokenLeaks) {
                                    blocking = true;
                                    // store counter into local storage
                                    storeCounter('thirdPartyTokenLeaks');
                                }
                                if (threats.CSRFAttack) {
                                    blocking = true;
                                    // store counter into local storage
                                    storeCounter("CSRF");
                                }
                            }
                            // block referer token leakage
                            var refererTokens = detectRefererTokenLeakage(dets);
                            if (refererTokens) {
                                blocking = true;
                                console.log(refererTokens);
                                // store referer leakage to the local storage
                                storeRefererTokenLeakage(refererTokens);
                                storeCounter('refererLeakage');
                                console.log('We blocked the above request because of referer token leakage!' );
                            }
                        }
                        // configure blocking behaviour
                        if (blocking){
                            console.log(oauth2Response);
                            console.log('We blocked the above request!' );
                        }
                        return { cancel: blocking };
                    },
                    { urls: ["<all_urls>"] },
                    ["blocking", "requestHeaders", "extraHeaders"]);
            }
        } else {
            // // SSL protection
            var isHTTPUpgrade = localStorage.getItem("https-options");
            if (parseInt(isHTTPUpgrade)) {
                var addSSL = sslProtect(details);
                if (addSSL) {
                    return addSSL;
                }
            }
        }
        // return {cancel: true};
    },
    { urls: ["<all_urls>"] },
    ["blocking", "requestBody"]);


chrome.webRequest.onBeforeSendHeaders.addListener(
    function (details) {
        // var headers = details.requestHeaders;
        // console.log(headers);
        var oauth2 = detectOAuth2(details);
        if (oauth2) {
            storeOAuth2Request(oauth2);
        }
        var url = details.url;
        var blocking = false;
        var oauth2Response = detectOAuth2Response(details);
        if (oauth2Response) {
            storeOAuth2Response(oauth2Response);
            var oauth2Request = localStorage.getItem(oauth2Response.RPDomain);
            if (oauth2Request) {
                oauth2Request = JSON.parse(oauth2Request).request;
                var threats = detectOAuth2Threats(oauth2Request, oauth2Response);
                // print threats to console
                printThreats(threats);
                if (threats.thirdPartyTokenLeaks) {
                    blocking = true;
                    // store counter into local storage
                    storeCounter('thirdPartyTokenLeaks');
                }
                if (threats.CSRFAttack) {
                    blocking = true;
                    // store counter into local storage
                    storeCounter("CSRF");
                }
            } else {
                var threats = detectOAuth2Threats(null, oauth2Response);
                // print threats to console
                printThreats(threats);
                if (threats.thirdPartyTokenLeaks) {
                    blocking = true;
                    // store counter into local storage
                    storeCounter('thirdPartyTokenLeaks');
                }
                if (threats.CSRFAttack) {
                    blocking = true;
                    // store counter into local storage
                    storeCounter("CSRF");
                }
            }
        }
        var refererTokens = detectRefererTokenLeakage(details);
        if (refererTokens) {
            blocking = true;
        }
        if (blocking){
            if(refererTokens){
                console.log(refererTokens);
                // store referer leakage data to local storage
                storeRefererTokenLeakage(refererTokens);
                storeCounter('refererLeakage');
                console.log('We blocked the above request because of referer token leakage!' );
            }else{
                console.log(oauth2Response);
                console.log('We blocked the above request!' );
            }

        }
        return {cancel: blocking};
        // console.log(details);
        // var oauth2Vul = detectOauth2Vuls(details);

        // if (oauth2) {
        //     // store the OAuth 2.0 object
        //     storeOAuth2ToCocalStorage(oauth2);
        // }else if(oauth2Response){
        //     storeOAuth2Response(oauth2Response);
        // }else if(oauth2Vul){
        //     storeOAuth2Vul(oauth2Vul);
        // }
    },
    { urls: ["<all_urls>"] },
    ["blocking", "requestHeaders", "extraHeaders"]);
/**
 * detect OAuth 2.0 response
 *
 * @param {object} domainRegs (the regular expression object)
 * @param {string} httpMessage (an http message)
 * @returns {'google.com': {'code':'4/.{43}'}}
 */
function isOAuth2Token(domainRegs, httpMessage) {
    const IdPs = Object.keys(domainRegs);
    var matches = {};
    for (let i = 0; i < IdPs.length; i++) {
        var tokens = {};
        const IdP = IdPs[i];
        const IdPRegs = domainRegs[IdP];
        Object.keys(IdPRegs).map(function (key) {
            const pattern = IdPRegs[key];
            const result = pattern.exec(httpMessage);
            if (result) {
                // console.log(result);
                tokens[key] = result[1] || result[2] || result[3] || result[4] || result[5] || result[6];
            }
        });
        if (Object.keys(tokens).length > 0) {
            // console.log(tokens);
            matches[IdP] = tokens;
        }
    }
    if (Object.keys(matches).length > 0) {
        // console.log(matches)
        return matches;
    } else {
        return null;
    }
}


/**
 * detect OAuth2.0 response in an HTTP message
 * @param  {object} details chrome webRequest detials object
 * @return {OAuth2Response object or null}         [description]
 */
function detectOAuth2Response(details) {
    // OAuth 2.0 response Object
    var OAuth2Response = {
        IdP: '',
        RPDomain: '',
        RPHost: '',
        RPProtocol: '',
        method: '',
        state: '',
        code: '',
        referer: '',
        access_token: '',
        id_token: '',
        responseURL: '',
        data: '',
        cookie: ''
    };
    var url = details.url;
    var response = new URL(url);
    var RPHost = response.host;
    var RPDomain = extractDomain(RPHost);
    var RPProtocol = response.protocol;
    var method = details.method;
    // Initialize the response object;
    OAuth2Response.RPDomain = RPDomain;
    OAuth2Response.RPHost = RPHost;
    OAuth2Response.RPProtocol = RPProtocol;
    OAuth2Response.method = method;
    OAuth2Response.responseURL = url;

    // retrieve IdPs and ignore requests send to IdP domains
    var IdPs = Object.keys(googleOAuth2RegsObject);
    // add googleapis.com into whitelist
    IdPs.push('googleapis.com');
    if (customizedRegsObjects) {
        var customizedIdPs = Object.keys(customizedRegsObjects);
        IdPs = IdPs.concat(customizedIdPs);
    }
    // return 0 if the url is sending info to IdPs
    if (IdPs.indexOf(extractDomain(RPHost)) >= 0) {
        return null;
    }
    // detect OAuth 2.0 response for different methods.
    if (method === 'GET') {
        // get method.
        // read customized regular expression.
        var isGoogle;
        if (customizedRegsObjects) {
            isGoogle = isOAuth2Token(customizedRegsObjects, details.url) || isOAuth2Token(googleOAuth2RegsObject, details.url);
        } else {
            isGoogle = isOAuth2Token(googleOAuth2RegsObject, details.url);
        }
        // console.log(isGoogle);
        if (isGoogle) {
            var IdP = Object.keys(isGoogle)[0];
            var tokens = isGoogle[IdP];
            for (let i = 0; i < Object.keys(tokens).length; i++) {
                const tokenName = Object.keys(tokens)[i];
                const tokenValue = tokens[tokenName];
                OAuth2Response[tokenName] = tokenValue;
            }
            OAuth2Response.IdP = IdP;
            // retrieve paramters from get request
            var params = new URLSearchParams(response.search);
            OAuth2Response.state = params.get("state");
            OAuth2Response.code = params.get("code");

            //retrieve referer header
            var headers = details.requestHeaders;
            // console.log(headers)
            var referer = "";
            var cookie = "";
            for (var i = 0; i < headers.length; i++) {
                var header = headers[i];
                if (header.name.toLowerCase() === "cookie") {
                    cookie = header["value"];
                } else if (header.name.toLowerCase() === "referer") {
                    referer = header["value"];
                }
            }
            var isToken = isOAuth2Token(googleOAuth2RegsObject, cookie);
            if (isToken) {
                OAuth2Response.cookie = cookie;
            }
            OAuth2Response.referer = referer;
            console.log(OAuth2Response);
            return OAuth2Response;
        } else {
            // return null if it is not an OAuth2 response
            return null;
        }
    } else if (method === 'POST') {
        // post method
        var requestBody = details.requestBody;
        var data = '';
        // get the requestbody from details.
        if (requestBody) {
            var formData = requestBody.formData;
            var rawData = requestBody.raw;
            var stringForm = '';
            if (formData) {
                var keys = Object.keys(formData);
                for (let i = 0; i < keys.length; i++) {
                    var keyValuePair = keys[i] + '=' + formData[keys[i]] + '&';
                    stringForm += keyValuePair;
                }
                // console.log('string form ' + stringForm)
            } else if (rawData.length > 0) {
                rawData = String.fromCharCode.apply(null, new Uint8Array(requestBody.raw[0].bytes));
                // console.log('string rawdata' + rawData);
            }
            data = stringForm || rawData;
        }
        // check OAuth2 response on data.
        if (data.length > 0) {
            // console.log(data);
            var isGoogle = isOAuth2Token(googleOAuth2RegsObject, data);
            if (isGoogle) {
                var IdP = Object.keys(isGoogle)[0];
                var tokens = isGoogle[IdP];
                for (let i = 0; i < Object.keys(tokens).length; i++) {
                    const tokenName = Object.keys(tokens)[i];
                    const tokenValue = tokens[tokenName];
                    OAuth2Response[tokenName] = tokenValue;
                }
                OAuth2Response.IdP = IdP;
                OAuth2Response.data = data;
                // console.log(OAuth2Response);
                return OAuth2Response;
            } else {
                // return null if not OAuth 2 response detected.
                return null
            }
        }
    } else {
        // other methods
        var isGoogle;
        if (customizedRegsObjects) {
            isGoogle = isOAuth2Token(customizedRegsObjects, details.url) || isOAuth2Token(googleOAuth2RegsObject, details.url);
        } else {
            isGoogle = isOAuth2Token(googleOAuth2RegsObject, details.url);
        }
        // console.log(isGoogle);
        if (isGoogle) {
            var IdP = Object.keys(isGoogle)[0];
            var tokens = isGoogle[IdP];
            for (let i = 0; i < Object.keys(tokens).length; i++) {
                const tokenName = Object.keys(tokens)[i];
                const tokenValue = tokens[tokenName];
                OAuth2Response[tokenName] = tokenValue;
            }
            OAuth2Response.IdP = IdP;
            // retrieve paramters from get request
            var params = new URLSearchParams(response.search);
            OAuth2Response.state = params.get("state");
            OAuth2Response.code = params.get("code");

            // retrieve referer header
            var headers = details.requestHeaders;
            // console.log(headers)
            var referer = "";
            var cookie = "";
            for (var i = 0; i < headers.length; i++) {
                var header = headers[i];
                if (header.name.toLowerCase() === "cookie") {
                    cookie = header["value"];
                } else if (header.name.toLowerCase() === "referer") {
                    referer = header["value"];
                }
            }
            var isToken = isOAuth2Token(googleOAuth2RegsObject, cookie);
            if (isToken) {
                OAuth2Response.cookie = cookie;
            }
            OAuth2Response.referer = referer;
            console.log(OAuth2Response);
            return OAuth2Response;
        } else {
            // return null if it is not an OAuth2 response
            return null;
        }
    }
}


/**
 * detect OAuth 2.0 Vulnerabilities
 * @param  {object} OAuthRequest  OAuth2.0 request object
 * @param  {object} OAuthResponse OAuth2.0 response object
 * @return {threats object}               threats object
 */
function detectOAuth2Threats(OAuthRequest, OAuthResponse) {
    var threats = {};
    var responseReferer = OAuthResponse.referer;
    // console.log(OAuthRequest)
    // console.log(OAuthResponse)
    // detect OAuth 2.0 vulnerabilities

    // detect unsafe token transfer
    if (OAuthResponse.RPProtocol === 'http:') {
        threats.unsafeTransferTokens = true;
    }

    // detect csrf and privacy leakage.
    if (OAuthRequest){
        if (OAuthResponse.RPProtocol === 'http:') {
            // do nothing here
        }
        else{
            if (responseReferer) {
                var responseRefererURL = new URL(responseReferer);
                var responseRefererDomain = extractDomain(responseRefererURL.host);
                var RPWhiteList = ["behance.net", "domraider.io", "miamiherald.com", "nj.com", "philips.co.uk", 'stackexchange.com',"stackoverflow.com",'tribdss.com', 'stackexchange.com', 'adobelogin.com', "gigya.com"];
                // white lists RPs that are changing domains.
                if (RPWhiteList.indexOf(responseRefererDomain) < 0) {
                    // console.log(responseRefererDomain);
                    // privacy beaches or CSRF attacks
                    if (responseRefererDomain !== OAuthResponse.RPDomain || responseRefererDomain !== OAuthResponse.IdP) {
                        // detect CSRF attacks
                        var redirect_uri = OAuthRequest.redirectURI;
                        if (redirect_uri === 'postmessage' || redirect_uri ==="iframerpc") {
                            // detect for RPs using the Google client library
                            var origin = OAuthRequest.origin;
                            if (origin.indexOf(responseRefererDomain) >= 0 || OAuthResponse.IdP.indexOf(responseRefererDomain) >= 0) {
                                // console.log("No CSRF attack detected!");
                            }else{
                                threats.CSRFAttack = true;
                            }
                        } else {
                            // detect for RPs not using the normal OAuth 2.0 Flow
                            if (redirect_uri.indexOf(responseRefererDomain) >= 0 || OAuthResponse.IdP.indexOf(responseRefererDomain) >= 0) {
                                    // console.log("No CSRF attack detected!");
                            }else{
                                threats.CSRFAttack = true;
                            }
                        }
                    }
                }
            }else{
                var responseDomain = OAuthResponse.RPDomain;
                var httpsRPUpgradeWhitelist = localStorage.getItem("httpsRPUpgradeWhitelist");
                if (httpsRPUpgradeWhitelist) {
                    httpsRPUpgradeWhitelist = JSON.parse(httpsRPUpgradeWhitelist);
                    if (httpsRPUpgradeWhitelist.indexOf(responseDomain) < 0) {
                        threats.CSRFAttack = true;
                    }
                }else{
                    threats.CSRFAttack = true;
                }

            }
        }
        // referer header is present in the response

    }else{
        // no OAuth 2.0 request is generated for the response domain, then it's a third party token leakage.
        // white RPs using sending tokens to another domain
        var RPWhiteList = ['stackoverflow.com', 'stackexchange.com']
        if (RPWhiteList.indexOf(OAuthResponse.RPDomain) < 0) {
            threats.thirdPartyTokenLeaks = true;
        }

    }
    // detect CSRF attack threat; if it's an third party token leakage, don't detect
    // if it's a post request, don't detect
    if (!threats.thirdPartyTokenLeaks) {
        if (!OAuthResponse.state && OAuthResponse.method !== 'POST') {
            threats.CSRFAttackThreat = true;
        }
        if (OAuthResponse.access_token) {
            threats.flowMisuse = true;
        }
        // Impersonation attacks threat detect
        if (OAuthResponse.access_token && !OAuthResponse.code && !OAuthResponse.id_token) {
            threats.impersonationAttack = true;
        }
    }
    return threats;
}

/**
 * detect referer token leakage
 * @param  {object} details [webRequest details object]
 * @return {"RefererTokenLeakage": {"google.com":{"code":"4/.{43}"}}
 * [return the object or null]
 */
function detectRefererTokenLeakage(details) {
    var headers = details.requestHeaders;
    // console.log(headers)
    var referer = "";
    for (var i = 0; i < headers.length; i++) {
        var header = headers[i];
        if (header.name.toLowerCase() === "referer") {
            referer = header["value"];
        }
    }
    if(referer){
        var refererTokens = isOAuth2Token(googleOAuth2RegsObject, referer);
        if(refererTokens){
            var refererURL = new URL(referer);
            var requestURL = new URL(details.url);
            var IdPWhiteList = ["google.com", "googleusercontent.com", "googleapis.com"]
            var RPWhiteList = ["logmeininc.com", "tribdss.com", "chicagotribune.com", "latimes.com", "trb.com"]

            var refererDomain = extractDomain(refererURL.host);
            var requestDomain = extractDomain(requestURL.host);
            // check request in the IdP whitelist
            if (IdPWhiteList.indexOf(requestDomain) >= 0){
                return null;
            }
            // check request in the RP whitelist
            if (RPWhiteList.indexOf(refererDomain) >= 0) {
                return null;
            }
            // check referer token leakage.
            if (requestDomain !== refererDomain) {
                console.log('Referer Token leakage detected!');
                return {"RefererTokenLeakage" : refererTokens, 'referer': referer, 'toURL': details.url};
            }else{
                return null;
            }
        }else{
            return null;
        }
    }else{
        return null;
    }
}

/**
 * store referer token leakage token into localStorage
 * @param  {object} referLeakage [an referTokenLeakage object]
 *
 */
function storeRefererTokenLeakage(referLeakage) {
    // body...
    var refererLeakages = localStorage.getItem('refererLeakage');
    if (refererLeakages){
        var storedRefererLeakages = JSON.parse(refererLeakages);
        storedRefererLeakages.push(referLeakage);
        localStorage.setItem('refererLeakage', JSON.stringify(storedRefererLeakages));
    }else{
        refererLeakages = [referLeakage];
        localStorage.setItem('refererLeakage', JSON.stringify(refererLeakages));
    }
}


function sslProtect(details) {
    var oauth2Response = detectGETSSL(details);
    var url = details.url;
    if (oauth2Response) {
        var oauth2Request = localStorage.getItem(oauth2Response.RPDomain);
        if (oauth2Request) {
            oauth2Request = JSON.parse(oauth2Request).request;
            var threats = detectOAuth2Threats(oauth2Request, oauth2Response);
            // print threats to console
            if (threats.unsafeTransferTokens) {
                // whitelist domains using http
                var host = new URL(url);
                var domain = extractDomain(host.host);
                var httpsRPUpgradeWhitelist = localStorage.getItem("httpsRPUpgradeWhitelist");
                if (httpsRPUpgradeWhitelist) {
                    httpsRPUpgradeWhitelist = JSON.parse(httpsRPUpgradeWhitelist);
                    if(httpsRPUpgradeWhitelist.indexOf(domain) < 0){
                        httpsRPUpgradeWhitelist.push(domain);
                    }
                    localStorage.setItem("httpsRPUpgradeWhitelist", JSON.stringify(httpsRPUpgradeWhitelist));
                }else{
                    localStorage.setItem("httpsRPUpgradeWhitelist", JSON.stringify([domain]));
                }
                // do redirection
                url = url.replace("http:", "https:");
                storeCounter("HTTPSUpgrade");
                console.log("OAuthGuard did HTTPs upgrade in : " + domain + " for the following OAuth 2.0 response:");
                return { redirectUrl: url };

            }
        } else {
            var threats = detectOAuth2Threats(null, oauth2Response);
            // print threats to console
            if (threats.unsafeTransferTokens) {
                // whitelist domains using http
                var host = new URL(url);
                var domain = extractDomain(host.host);
                var httpsRPUpgradeWhitelist = localStorage.getItem("httpsRPUpgradeWhitelist");
                if (httpsRPUpgradeWhitelist) {
                    httpsRPUpgradeWhitelist = JSON.parse(httpsRPUpgradeWhitelist);
                    if(httpsRPUpgradeWhitelist.indexOf(domain) < 0){
                        httpsRPUpgradeWhitelist.push(domain);
                    }
                    localStorage.setItem("httpsRPUpgradeWhitelist", JSON.stringify(httpsRPUpgradeWhitelist));
                }else{
                    localStorage.setItem("httpsRPUpgradeWhitelist", JSON.stringify([domain]));
                }
                // do redirection
                url = url.replace("http:", "https:")
                storeCounter("HTTPSUpgrade");
                console.log("OAuthGuard did HTTPs upgrade in : " + domain + " for the following OAuth 2.0 response:");
                return { redirectUrl: url };
            }
        }
    }
}

/**
 * store counter into local storage
 * @param  {string} threatName the threat name, e.g. CSRF
 *
 */
function storeCounter(threatName) {
    var counterName = threatName+'Counter';
    var blockingCount = localStorage.getItem(counterName);
    if (blockingCount) {
        blockingCount = parseInt(blockingCount);
        blockingCount += 1;
        localStorage.setItem(counterName, blockingCount);
    }else{
        blockingCount = 1;
        localStorage.setItem(counterName, blockingCount);
    }
}

function printThreats(threats) {
    var threatNames = Object.keys(threats);
    var msg = ''
    if (threatNames.length > 0) {
        for (let i = 0; i < threatNames.length; i++) {
            const threatName = threatNames[i];
            msg += threatName + ';';
        }
        console.warn('threats detected: ' + msg);
    }
}


function detectGETSSL(details) {
    // OAuth 2.0 response Object
    var OAuth2Response = {
        IdP: '',
        RPDomain: '',
        RPHost: '',
        RPProtocol: '',
        method: '',
        state: '',
        code: '',
        referer: '',
        access_token: '',
        id_token: '',
        responseURL: '',
        data: '',
        cookie: ''
    };
    var url = details.url;
    var response = new URL(url);
    var RPHost = response.host;
    var RPDomain = extractDomain(RPHost);
    var RPProtocol = response.protocol;
    var method = details.method;
    // Initialize the response object;
    OAuth2Response.RPDomain = RPDomain;
    OAuth2Response.RPHost = RPHost;
    OAuth2Response.RPProtocol = RPProtocol;
    OAuth2Response.method = method;
    OAuth2Response.responseURL = url;

    // retrieve IdPs and ignore requests send to IdP domains
    var IdPs = Object.keys(googleOAuth2RegsObject);
    // add googleapis.com into whitelist
    IdPs.push('googleapis.com');
    if (customizedRegsObjects) {
        var customizedIdPs = Object.keys(customizedRegsObjects);
        IdPs = IdPs.concat(customizedIdPs);
    }
    // return 0 if the url is sending info to IdPs
    if (IdPs.indexOf(extractDomain(RPHost)) >= 0) {
        return null;
    }
    // detect OAuth 2.0 response for different methods.
    if (method === 'GET') {
        // get method.
        // read customized regular expression.
        var isGoogle;
        if (customizedRegsObjects) {
            isGoogle = isOAuth2Token(customizedRegsObjects, details.url) || isOAuth2Token(googleOAuth2RegsObject, details.url);
        } else {
            isGoogle = isOAuth2Token(googleOAuth2RegsObject, details.url);
        }
        // console.log(isGoogle);
        if (isGoogle) {
            var IdP = Object.keys(isGoogle)[0];
            var tokens = isGoogle[IdP];
            for (let i = 0; i < Object.keys(tokens).length; i++) {
                const tokenName = Object.keys(tokens)[i];
                const tokenValue = tokens[tokenName];
                OAuth2Response[tokenName] = tokenValue;
            }
            OAuth2Response.IdP = IdP;
            // retrieve paramters from get request
            var params = new URLSearchParams(response.search);
            OAuth2Response.state = params.get("state");
            OAuth2Response.code = params.get("code");
            return OAuth2Response;
        } else {
            // return null if it is not an OAuth2 response
            return null;
        }
    }
}
/*
 * detectOAuth2() - called on every url
 * returns an OAuth2 request object if the url is an OAuth 2.0 request
 * @param {String} url The url of an HTTP request
 * @return {OAuth 2.0  Request Object or null} The OAuth 2.0 Object decoded from the url request
 */
function detectOAuth2(details) {
    var OAuth2Request = {
        IdP: null,
        IdPProtocol: null,
        RP: null,
        RPDomain: null,
        RPProtocol: null,
        clientID: null,
        redirectURI: null,
        scope: null,
        state: null,
        origin: null,
        responseType: null,
        requestURL: null,
        referer: null
    }
    var url = details.url;
    var request = new URL(url);

    // detect whether the request is an OAuth 2.0 request
    if ((request.pathname.search(/oauth/i) >= 0) && (request.search.search(/redirect_uri/i) >= 0)) {
        // it's an OAuth 2.0 Request
        OAuth2Request.IdP = request.origin;
        OAuth2Request.requestURL = request.href;
        OAuth2Request.IdPProtocol = request.protocol;
        var params = new URLSearchParams(request.search);

        // deal with the RP and RP domain in the request object
        var redirect_uri = params.get("redirect_uri");
        var RPUrl;

        if (redirect_uri === "postmessage") {
            OAuth2Request.origin = params.get("origin");
            RPUrl = new URL(params.get("origin"));

        } else if (isURL(redirect_uri)) {
            RPUrl = new URL(redirect_uri);
        } else if (redirect_uri.indexOf("storagerelay") >= 0) {
            // deal with RP using the Google quick start example.
            var concatRelay = redirect_uri.replace("storagerelay://", "");// remove storagerelay from redirect_uri
            var originUrl = concatRelay.replace("/", "://");// reconstruct the URI.
            var origin = new URL(originUrl);
            OAuth2Request.origin = origin.origin;
            console.log("This is a strange OAuth 2.0 request using the Google quick start example! with redirect_uri: " + origin.origin);
            RPUrl = new URL(origin.origin);
            // set the redirect_uri to postmessage to make it compatible with postmessage flow.
            redirect_uri = "postmessage";

        }

        // console.log(RPUrl);

        OAuth2Request.RP = RPUrl.host;
        OAuth2Request.RPProtocol = RPUrl.protocol;
        OAuth2Request.RPDomain = extractDomain(RPUrl.host);
        var headers = details.requestHeaders;
        var referer = "";
        var cookie = "";
        for (var i = 0; i < headers.length; i++) {
            var header = headers[i];
            if (header.name.toLowerCase() === "cookie") {
                cookie = header["value"];
            } else if (header.name.toLowerCase() === "referer") {
                referer = header["value"];
            }
        }
        OAuth2Request.referer = referer;
        // update the OAuth 2.0 Object with the detected request values
        OAuth2Request.clientID = params.get("client_id");
        OAuth2Request.redirectURI = redirect_uri;
        OAuth2Request.scope = params.get("scope");
        OAuth2Request.state = params.get("state");
        OAuth2Request.responseType = params.get("response_type");
        console.log(OAuth2Request);
        return OAuth2Request;
    } else if ((request.pathname.search(/oauth/i) >= 0) && (request.search.search(/origin/i) >= 0) && (request.search.search(/client_id/i) >= 0)) {
        // console.log("This is not an OAuth 2.0 Request!");
        OAuth2Request.IdP = request.origin;
        OAuth2Request.requestURL = request.href;
        OAuth2Request.IdPProtocol = request.protocol;

        var headers = details.requestHeaders;
        var referer = "";
        var cookie = "";
        for (var i = 0; i < headers.length; i++) {
            var header = headers[i];
            if (header.name.toLowerCase() === "cookie") {
                cookie = header["value"];
            } else if (header.name.toLowerCase() === "referer") {
                referer = header["value"];
            }
        }
        OAuth2Request.referer = referer;


        var params = new URLSearchParams(request.search);
        OAuth2Request.origin = params.get("origin");
        OAuth2Request.clientID = params.get("client_id");
        OAuth2Request.scope = params.get("scope");
        OAuth2Request.redirectURI = "iframerpc";
        OAuth2Request.state = params.get("state");
        OAuth2Request.responseType = params.get("response_type") || params.get("action");

        var RPUrl = new URL(params.get("origin"));
        OAuth2Request.RP = RPUrl.host;
        OAuth2Request.RPProtocol = RPUrl.protocol;
        OAuth2Request.RPDomain = extractDomain(RPUrl.host);


        console.log(OAuth2Request);
        return OAuth2Request;
    }else{
        return null;
    }
}


/**
 * [storeOAuth2Request stores OAuth2.0 Request to local storage]
 * @param  {[Object]} oauth2request OAuth 2.0 Request Object
 *
 */
function storeOAuth2Request(oauth2request) {
    var RP = oauth2request.RPDomain;
    // more logic needs to be implemented to distinguish a normal request or a malicious request.
    if (typeof (localStorage) == 'undefined') {
        console.log('Your browser does not support HTML5 localStorage. Try upgrading.');
    }
    else {
        if(oauth2request.IdP.indexOf(RP) >=0){
            // if RP and IdP has the same domain, ignores it.
            return;
        }
        var OAuth2Records = localStorage.getItem(RP);
        if (OAuth2Records) {
            var storedOAuth2Records = JSON.parse(OAuth2Records);
            storedOAuth2Records.request = oauth2request;
            localStorage.setItem(RP, JSON.stringify(storedOAuth2Records));
        } else {
            var OAuth2Records = {};
            OAuth2Records.request = oauth2request;
            localStorage.setItem(RP, JSON.stringify(OAuth2Records));
        }
    }
}

/*
 * storeOAuth2Response  store OAuth2.0 Response Object to local storage.
 * @param {OAuth2ResposneObject} OAuth 2.0 Response Object
 *
 */

function storeOAuth2Response(oauth2response) {
    var RP = oauth2response.RPDomain;
    var OAuth2Records = localStorage.getItem(RP);
    if (OAuth2Records){
        var storedOAuth2Records = JSON.parse(OAuth2Records);
        if (storedOAuth2Records.response){
            storedOAuth2Records.response.push(oauth2response);
            localStorage.setItem(RP, JSON.stringify(storedOAuth2Records));
        }else{
            storedOAuth2Records.response = [oauth2response];
            localStorage.setItem(RP, JSON.stringify(storedOAuth2Records));
        }
    }else{
        // intentional privacy leakage .
        console.log("An privacy leakage detected!");
        var privacyRecords = localStorage.getItem('privacy');
        if (privacyRecords) {
            var storedPrivacyRecords = JSON.parse(privacyRecords);
            storedPrivacyRecords.push(oauth2response);
            localStorage.setItem('privacy', JSON.stringify(storedPrivacyRecords));
        }else{
            var privacyRecords = [oauth2response];
            localStorage.setItem('privacy', JSON.stringify(privacyRecords));
        }
    }
}



/*
 * Domain name extractor. Turns host names into domain names
 * Adapted from Chris Zarate's public domain genpass tool:
 *  http://labs.zarate.org/passwd/
 */


function extractDomain(host) {
    var s;  // the final result
    // Begin Chris Zarate's code
    var host = host.split('.');
    if (host[2] != null) {
        s = host[host.length - 2] + '.' + host[host.length - 1];
        domains = 'ab.ca|ac.ac|ac.at|ac.be|ac.cn|ac.il|ac.in|ac.jp|ac.kr|ac.nz|ac.th|ac.uk|ac.za|adm.br|adv.br|agro.pl|ah.cn|aid.pl|alt.za|am.br|arq.br|art.br|arts.ro|asn.au|asso.fr|asso.mc|atm.pl|auto.pl|bbs.tr|bc.ca|bio.br|biz.pl|bj.cn|br.com|cn.com|cng.br|cnt.br|co.ac|co.at|co.il|co.in|co.jp|co.kr|co.nz|co.th|co.uk|co.za|com.au|com.br|com.cn|com.ec|com.fr|com.hk|com.mm|com.mx|com.pl|com.ro|com.ru|com.sg|com.tr|com.tw|cq.cn|cri.nz|de.com|ecn.br|edu.au|edu.cn|edu.hk|edu.mm|edu.mx|edu.pl|edu.tr|edu.za|eng.br|ernet.in|esp.br|etc.br|eti.br|eu.com|eu.lv|fin.ec|firm.ro|fm.br|fot.br|fst.br|g12.br|gb.com|gb.net|gd.cn|gen.nz|gmina.pl|go.jp|go.kr|go.th|gob.mx|gov.br|gov.cn|gov.ec|gov.il|gov.in|gov.mm|gov.mx|gov.sg|gov.tr|gov.za|govt.nz|gs.cn|gsm.pl|gv.ac|gv.at|gx.cn|gz.cn|hb.cn|he.cn|hi.cn|hk.cn|hl.cn|hn.cn|hu.com|idv.tw|ind.br|inf.br|info.pl|info.ro|iwi.nz|jl.cn|jor.br|jpn.com|js.cn|k12.il|k12.tr|lel.br|ln.cn|ltd.uk|mail.pl|maori.nz|mb.ca|me.uk|med.br|med.ec|media.pl|mi.th|miasta.pl|mil.br|mil.ec|mil.nz|mil.pl|mil.tr|mil.za|mo.cn|muni.il|nb.ca|ne.jp|ne.kr|net.au|net.br|net.cn|net.ec|net.hk|net.il|net.in|net.mm|net.mx|net.nz|net.pl|net.ru|net.sg|net.th|net.tr|net.tw|net.za|nf.ca|ngo.za|nm.cn|nm.kr|no.com|nom.br|nom.pl|nom.ro|nom.za|ns.ca|nt.ca|nt.ro|ntr.br|nx.cn|odo.br|on.ca|or.ac|or.at|or.jp|or.kr|or.th|org.au|org.br|org.cn|org.ec|org.hk|org.il|org.mm|org.mx|org.nz|org.pl|org.ro|org.ru|org.sg|org.tr|org.tw|org.uk|org.za|pc.pl|pe.ca|plc.uk|ppg.br|presse.fr|priv.pl|pro.br|psc.br|psi.br|qc.ca|qc.com|qh.cn|re.kr|realestate.pl|rec.br|rec.ro|rel.pl|res.in|ru.com|sa.com|sc.cn|school.nz|school.za|se.com|se.net|sh.cn|shop.pl|sk.ca|sklep.pl|slg.br|sn.cn|sos.pl|store.ro|targi.pl|tj.cn|tm.fr|tm.mc|tm.pl|tm.ro|tm.za|tmp.br|tourism.pl|travel.pl|tur.br|turystyka.pl|tv.br|tw.cn|uk.co|uk.com|uk.net|us.com|uy.com|vet.br|web.za|web.com|www.ro|xj.cn|xz.cn|yk.ca|yn.cn|za.com';
        domains = domains.split('|');
        for (var i = 0; i < domains.length; i++) {
            if (s == domains[i]) {
                s = host[host.length - 3] + '.' + s;
                break;
            }
        }
    } else {
        s = host.join('.');
    }
    // End Chris Zarate's code
    return s;
}


/*
 * check whether a string is URL.
 */

function isURL(str) {
    var pattern = new RegExp('^(https?:\\/\\/)?' + // protocol
        '((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.?)+[a-z]{2,}|' + // domain name
        '((\\d{1,3}\\.){3}\\d{1,3}))' + // OR ip (v4) address
        '(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*' + // port and path
        '(\\?[;&a-z\\d%_.~+=-]*)?' + // query string
        '(\\#[-a-z\\d_]*)?$', 'i'); // fragment locator
    return pattern.test(str);
}





