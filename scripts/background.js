console.log("Hello, World!");

const googleOAuth2RegsObject = {
    'google.com': {
        access_token: new RegExp('(ya29\..{124,127})'),
        code: new RegExp('(?:code=)(4/\..{42})|(?:code=)(4%2F\..{42})|(?:code": ?")(4/\..{42})|(?:code": ?")(4%2F\..{42})'),
        id_token: /(eyJ.*\.eyJ.*\..{342})/
    }
};

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
                        if (dets.method === "POST" && requestId === detReuqestId) {
                            // console.log("This is a request for the POST rquest with requestId " + requestId);
                            var headers = dets.requestHeaders;
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
                            var oauth2Request = localStorage.getItem(oauth2Response.RPDomain);
                            if (oauth2Request) {
                                oauth2Request = JSON.parse(oauth2Request).request;
                                var threats = detectOAuth2Threats(oauth2Request, oauth2Response);
                                printThreats(threats);
                                if (threats.thirdPartyTokenLeaks) {
                                    blocking = true;
                                }
                                if (threats.CSRFAttack) {
                                    blocking = true;
                                }
                            } else {
                                var threats = detectOAuth2Threats(null, oauth2Response);
                                printThreats(threats);
                                if (threats.thirdPartyTokenLeaks) {
                                    blocking = true;
                                }
                                if (threats.CSRFAttack) {
                                    blocking = true;
                                }
                            }
                        }
                    },
                    { urls: ["<all_urls>"] },
                    ["blocking", "requestHeaders"]);
            }
        } else {
            // SSL protection
            // var addSSL = sslProtect(details);
            // if (addSSL) {
            //     return addSSL;
            // }
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
            var oauth2Request = localStorage.getItem(oauth2Response.RPDomain);
            if (oauth2Request) {
                oauth2Request = JSON.parse(oauth2Request).request;
                var threats = detectOAuth2Threats(oauth2Request, oauth2Response);
                // print threats to console
                printThreats(threats);
                if (threats.thirdPartyTokenLeaks) {
                    blocking = true;
                }
                if (threats.CSRFAttack) {
                    blocking = true;
                }
            } else {
                var threats = detectOAuth2Threats(null, oauth2Response);
                // print threats to console
                printThreats(threats);
                if (threats.thirdPartyTokenLeaks) {
                    blocking = true;
                }
                if (threats.CSRFAttack) {
                    blocking = true;
                }
            }
        }
        return { cancel: blocking };
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
    ["blocking", "requestHeaders"]);
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
                tokens[key] = result[1] || result[2] || result[3] || result[4];
            }
        });
        if (Object.keys(tokens).length > 0) {
            // console.log(tokens);
            matches[IdP] = tokens;
        }
    }
    if (Object.keys(matches).length > 0) {
        return matches;
    } else {
        return null;
    }
}

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
                console.log('string form ' + stringForm)
            } else if (rawData.length > 0) {
                rawData = String.fromCharCode.apply(null, new Uint8Array(requestBody.raw[0].bytes));
                console.log('string rawdata' + rawData);
            }
            data = stringForm || rawData;
        }
        // check OAuth2 response on data.
        if (data.length > 0) {
            console.log(data);
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

function detectOAuth2Threats(OAuthRequest, OAuthResponse) {
    var threats = {};
    var responseReferer = OAuthResponse.referer;
    // console.log(OAuthRequest)
    // console.log(OAuthResponse)
    // referer is presented
    if (responseReferer) {
        var responseRefererURL = new URL(responseReferer);
        var responseRefererDomain = extractDomain(responseRefererURL.host);
        // privacy beaches or CSRF attacks
        if (responseRefererDomain !== OAuthResponse.RPDomain || responseRefererDomain !== OAuthResponse.IdP) {
            if (OAuthRequest) {
                // CSRF attacks
                var redirect_uri = OAuthRequest.redirectURI;
                if (redirect_uri === 'postmessage') {
                    // detect for RPs using the Google client library
                    var origin = OAuthRequest.origin;
                    if (origin.indexOf(responseRefererDomain) < 0) {
                        threats.CSRFAttack = true;
                    }
                } else {
                    // detect for RPs not using the Google client library
                    if (redirect_uri.indexOf(responseRefererDomain) < 0) {
                        threats.CSRFAttack = true;
                    }
                }
            } else {
                // privacy breaches
                threats.thirdPartyTokenLeaks = true;

            }
        } else {
            console.log('The OAuth2.0 response seems ok');
        }
    } else {
        if (OAuthResponse.RPProtocol === 'http:') {
            threats.unsafeTransferTokens = true;
        }
        // referer header is compressed.
    }
    // Impersonation attacks threat detect
    if (OAuthResponse.access_token && !OAuthResponse.code && !OAuthResponse.id_token) {
        threats.impersonationAttack = true;
    }

    if (!OAuthResponse.state && OAuthResponse.method !== 'POST') {
        threats.CSRFAttackThreat = true;
    }
    if (OAuthResponse.access_token || OAuthResponse.id_token) {
        threats.flowMisuse = true;
    }

    return threats;
}


function sslProtect(details) {
    var oauth2Response = detectGETSSL(details);
    var url = details.url
    if (oauth2Response) {
        var oauth2Request = localStorage.getItem(oauth2Response.RPDomain);
        if (oauth2Request) {
            oauth2Request = JSON.parse(oauth2Request).request;
            var threats = detectOAuth2Threats(oauth2Request, oauth2Response);
            console.log('here')
            // print threats to console
            if (threats.unsafeTransferTokens) {
                url = url.replace("http:", "https:")
                return { redirectUrl: url }

            }
        } else {
            var threats = detectOAuth2Threats(null, oauth2Response);
            // print threats to console
            if (threats.unsafeTransferTokens) {
                url = url.replace("http:", "https:")
                return { redirectUrl: url }
            }
        }
    } else {
        return null;
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
 * @return {OAuth 2.0  Request Object} The OAuth 2.0 Object decoded from the url request
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
    } else {
        // console.log("This is not an OAuth 2.0 Request!");
        return null;
    }
}



/*
 * detectOAuth2Request- called on every url
 * returns an OAuth2 response object if the url is an OAuth 2.0 response
 * @param {isform:true; data:formdata; details: webrequest details}
 * @return {OAuth 2.0 Response Object} The OAuth 2.0 Object decoded from the url request
 */
function detectPostOAuth2Response(isform, data, details) {
    // define the OAuth 2.0 Response Object
    var OAuth2Response = {
        IdP: null,
        IdPProtocol: null,
        RP: null,
        RPDomain: null,
        RPProtocol: null,
        requestHeaders: null,
        method: "POST",
        formData: null,
        JSONData: null,
        responseURL: null,
        type: null,
        requestHeaders: null
    }
    /*
     *  a sample OAuth2 response
     *  "https://oauth.theguardian.com/facebook/auth-callback?
     * code=AQCXBhkF9pE-AyzQhrYRhvpQ_uWyGgQOP-coX1sZXOCMSsqOlCN48v7Y3N58m1TB_e4IdnXgc3MegBY9BlssPysJCnaLk56Q_o1GIJLZiyzhVqxrgoKwrPayHrSwqaEU3XvMdhWilcAarlPSOfIwQtCUK-xNbdendOAQe8mzlidJxN5VFpkCZgrgQI1Ss-uvJSHUDPYpod6Eie_WGA4wA8fpjEJ0VLbjKApEZXocuAsRl3HUiuc1UlW9khIGoPAL21KeFb6mMKi9Q8Wjfk_a707irFXWITDKBla21Ygf9tpGCC1njiwm0jev_7S1mj2dDI_CuANPOv2wib3ArJRmGVs6
     * &state=eyJyZXR1cm5VcmwiOiJodHRwczovL3d3dy50aGVndWFyZGlhbi5jb20vdWsiLCJ0b2tlbiI6InBpaXY3ZTdwdHA2dWlxdnBnYjk0ZGEwNjNuIn0#_=_"
     */

    var extractedFacebookFormData;
    var extractedGoogleFormData;

    var extractedFacebookJSONData;
    var extractedGoogleJSONData;
    var headers = details.requestHeaders;

    if (isform) {
        extractedGoogleFormData = extractGoogleFormData(data);
        extractedFacebookFormData = extractFacebookFormData(data, headers);
        extractedGoogleJSONData = null;
        extractedFacebookJSONData = null;
    } else {
        extractedGoogleJSONData = extractGoogleJSONData(data);
        extractedFacebookJSONData = extractFaceBookJSONData(data, headers);
        extractedGoogleFormData = null;
        extractedFacebookFormData = null;
        try {
            // JSON.parse(extractedFacebookJSONData);
            JSON.parse(extractedGoogleJSONData);
        } catch (err) {
            // console.log("can not parse the JSON Data");
            // return immediately when the post data is not JSON format.
            extractedGoogleJSONData = null;
        }
        try {
            // JSON.parse(extractedFacebookJSONData);
            JSON.parse(extractedFacebookJSONData);
        } catch (err) {
            // console.log("can not parse the JSON Data");
            // return immediately when the post data is not JSON format.
            extractedFacebookJSONData = null;
        }
    }
    var response = new URL(details.url);
    var RPHost = response.host;

    var redirectData = extraceRedirectURLs(RPHost);
    var redirectURLs = redirectData["URLs"];
    var origin = redirectData["origin"];
    // console.log(redirectURLs);

    var IdP;
    if (redirectURLs) {
        // this is to detect the response from Google's postmessage API.
        var IdPs = Object.keys(redirectURLs);
        for (var i = 0; i < IdPs.length; i++) {
            var originUrl = new URL(redirectURLs[IdPs[i]]);
            var urlNoProtocol = originUrl.host + originUrl.pathname;
            var extractedIdP = IdPs[i];

            if (extractedIdP === "https://accounts.google.com") {
                // check post data containing a Google OAuth 2.0 response.
                if (extractedGoogleFormData && (response.host + response.pathname).indexOf(urlNoProtocol) >= 0) {
                    // this is to verify the redirect_uri == origin
                    IdP = "https://accounts.google.com";
                    console.log("This is a Google OAuth 2.0 Response using POST method (origin == redirect_uri) for RP: " + response.origin + response.pathname + " from IdP : " + IdP + " Using Google's postmessage API!");
                } else if (extractedGoogleFormData && extractDomain(response.host) === extractDomain(originUrl.host)) {
                    // This is used to support redirect_uri is different from the registered origin.
                    IdP = "https://accounts.google.com";
                    console.log("This is a Google OAuth 2.0 Response using POST method (orign != redirect_uri) for RP: " + response.origin + response.pathname + " from IdP : " + IdP + " using Google's postmessage API!");
                } else if (extractedGoogleJSONData && (response.host + response.pathname).indexOf(urlNoProtocol) >= 0) {
                    IdP = "https://accounts.google.com";
                    console.log("This is a Google OAuth 2.0 Response using POST method with JSONData (origin == redirect_uri) for RP: " + response.origin + response.pathname + " from IdP : " + IdP + " Using Google's postmessage API!");
                } else if (extractedGoogleJSONData && extractDomain(response.host) === extractDomain(originUrl.host)) {
                    IdP = "https://accounts.google.com";
                    console.log("This is a Google OAuth 2.0 Response using POST method with JSONData (orign != redirect_uri) for RP: " + response.origin + response.pathname + " from IdP : " + IdP + " using Google's postmessage API!");
                } else {
                    continue;
                }

            } else if (extractedIdP === "https://www.facebook.com") {
                // console.log("inside the facebook IdP ");
                // check check post data containing a Facebook OAuth 2.0 response.
                if (extractedFacebookFormData && (response.host + response.pathname).indexOf(urlNoProtocol) >= 0) {
                    //deal with Facebook Post
                    // this is to verify the redirect_uri == origin
                    IdP = "https://www.facebook.com";
                    console.log("This is an Facebook OAuth 2.0 Response using POST method (origin == redirect_uri) for RP: " + response.origin + response.pathname + " from IdP : " + IdP + " Using Facebook's postmessage API!");
                } else if (extractedFacebookFormData && extractDomain(response.host) === extractDomain(originUrl.host)) {
                    // This is used to support redirect_uri is different from the registered origin.
                    IdP = "https://www.facebook.com";
                    console.log("This is an Facebook OAuth 2.0 Response using POST method (orign != redirect_uri) for RP: " + response.origin + response.pathname + " from IdP : " + IdP + " using Facebook's postmessage API!");
                } else if (extractedFacebookJSONData && (response.host + response.pathname).indexOf(urlNoProtocol) >= 0) {
                    IdP = "https://www.facebook.com";
                    console.log("This is an Facebook OAuth 2.0 Response using POST method with JSONData (origin == redirect_uri) for RP: " + response.origin + response.pathname + " from IdP : " + IdP + " Using Facebook's postmessage API!");
                } else if (extractedFacebookJSONData && extractDomain(response.host) === extractDomain(originUrl.host)) {
                    IdP = "https://www.facebook.com";
                    console.log("This is an Facebook OAuth 2.0 Response using POST method with JSONData (orign != redirect_uri) for RP: " + response.origin + response.pathname + " from IdP : " + IdP + " using Facebook's postmessage API!");
                } else {
                    continue;
                }
            }
        }

        if (IdP) {
            // update the OAuth 2 response object.
            OAuth2Response.IdP = IdP;
            var IdPhost = new URL(IdP);
            OAuth2Response.IdPProtocol = IdPhost.protocol;
            OAuth2Response.RP = response.host;
            OAuth2Response.RPDomain = extractDomain(response.host);
            OAuth2Response.RPProtocol = response.protocol;
            OAuth2Response.responseURL = response.href;
            OAuth2Response.method = details.method;
            OAuth2Response.requestHeaders = details.requestHeaders;
            // console.log(extractedGoogleJSONData|| extractedFacebookJSONData);

            // find the parameters
            OAuth2Response.formData = extractedGoogleFormData || extractedFacebookFormData;
            OAuth2Response.JSONData = JSON.parse(extractedGoogleJSONData || extractedFacebookJSONData);
            OAuth2Response.type = details.type;
            console.log(OAuth2Response);
            return OAuth2Response;
        }
    } else {
        // console.log("This is not an OAuth 2.0 Response!");
        return 0;
    }
}

/*
 * detectOAuth2Request- called on every url
 * returns an OAuth2 VUl object
 * @param {details: webrequest details}
 * @return {OAuth 2.0 Vul Object} The OAuth 2.0 Object decoded from the url request
 */

function detectOauth2Vuls(details) {

    var OAuth2Vul = {
        CSRF: null,
        IDLogin: null,
        redirectURIMismatch: null,
        flowMisuse: null,
        clientSecretLeak: null,
        accessTokenLeak: null,
        refererLeak: null,
        codeLeak: null,
        idTokenLeak: null,
        RP: null,
        RPDomain: null,
        RPRequest: null,
        IdP: null,
        isVul: null
    }

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
    // check whether token is leaked to another domain.
    var request_url = new URL(details.url);
    var requestHost = request_url.host;
    if (referer) {
        var referer_url = new URL(referer);
        var refererHost = referer_url.host;
        // console.log(refererHost)
        if (extractDomain(refererHost) != extractDomain(requestHost) && (isGoogleCode(referer) || isGoogleIDToken(referer) || isGoogleAccessToken(referer))) {
            console.log("The request leak Google tokens to a third party.");
            OAuth2Vul.RPDomain = extractDomain(refererHost);
            OAuth2Vul.IdP = "https://accounts.google.com";
            OAuth2Vul.refererLeakTo = request_url.href;
            OAuth2Vul.refererLeak = referer;
        } else if (extractDomain(refererHost) != extractDomain(requestHost) && (isFacebookCode(referer) || isFacebookAccessToken(referer) || isFacebookSignedRequestInHeader(referer))) {
            console.log("The request leak Facebook tokens to a third party.");
            OAuth2Vul.RPDomain = extractDomain(refererHost);
            OAuth2Vul.IdP = "https://www.facebook.com";
            OAuth2Vul.refererLeak = referer;
            OAuth2Vul.refererLeakTo = request_url.href;
        }
    }


    // detect cookie leak
    if (isGoogleAccessToken(cookie) && request_url.protocol === "http:") {
        console.log("The request leak Google access token to a passive web attacker party through cookie.");
        OAuth2Vul.RPDomain = extractDomain(requestHost);
        OAuth2Vul.IdP = "https://accounts.google.com";
        OAuth2Vul.RP = request_url.href;
        OAuth2Vul.cookieLeak = cookie;
    } else if (isGoogleIDToken(cookie) && request_url.protocol === "http:") {
        console.log("The request leak Google access token to a passive web attacker party through cookie.");
        OAuth2Vul.RPDomain = extractDomain(requestHost);
        OAuth2Vul.IdP = "https://accounts.google.com";
        OAuth2Vul.RP = request_url.href;
        OAuth2Vul.cookieLeak = cookie;
    } else if (isFacebookAccessToken(cookie) && request_url.protocol === "http:") {
        console.log("The request leak Facebook access token to a passive web attacker party through cookie.");
        OAuth2Vul.RPDomain = extractDomain(requestHost);
        OAuth2Vul.RP = request_url.href;
        OAuth2Vul.IdP = "https://www.facebook.com";
        OAuth2Vul.cookieLeak = cookie;
    } else if (isFacebookSignedRequestInHeader(cookie) && request_url.protocol === "http:") {
        console.log("The request leak Facebook signed request to a passive web attacker party through cookie.");
        OAuth2Vul.RPDomain = extractDomain(requestHost);
        OAuth2Vul.IdP = "https://www.facebook.com";
        OAuth2Vul.RP = request_url.href;
        OAuth2Vul.cookieLeak = cookie;
    }

    if (OAuth2Vul.RP) {
        console.log(OAuth2Vul);
        return OAuth2Vul;
    } else {
        return 0;
    }

}




/*
 * storeOAuth2ToCocalStorage  store OAuth2.0 Object to local storage.
 * returns Oauth2request object if successfully stored otherwise 0
 * @param {OAuth2RequestObject}
 *
 */

function storeOAuth2Request(oauth2request) {
    var RP = oauth2request.RPDomain;
    // more logic needs to be implemented to distinguish a normal request or a malicious request.
    if (typeof (localStorage) == 'undefined') {
        console.log('Your browser does not support HTML5 localStorage. Try upgrading.');
    }
    else {
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
 * returns 1 if successfully stored otherwise 0
 * @param {OAuth2ResposneObject}
 *
 */

function storeOAuth2Response(oauth2response) {
    var response = oauth2response;
    var RPDomain = response.RPDomain;
    try {
        var rpSupportIdPs = localStorage.getItem(RPDomain + ":response");
        if (rpSupportIdPs) {
            var supportIdPs = JSON.parse(rpSupportIdPs);
            if (containsOAuth2(response, supportIdPs)) {
                // console.log(response);
                console.log("A response from IdP: " + response.IdP + "on RP: " + RPDomain + " has been stored before!!!!");
            } else {
                supportIdPs.push(response);
                localStorage.setItem(RPDomain + ":response", JSON.stringify(supportIdPs));
                console.log("New response from IdP :" + response.IdP + " has been found on RP : " + RPDomain + ", it is now being stored in the local storage.");

            }

        } else {
            localStorage.setItem(RPDomain + ":response", JSON.stringify([response]));
            console.log("OAuth2.0 response has been found and writes to localstorage");
        }
    }
    catch (e) {
        console.log(e);
    }
}


/*
 * storeOAuth2Response  store OAuth2.0 Response Object to local storage.
 * returns 1 if successfully stored otherwise 0
 * @param {OAuth2VuleObject}
 *
 */

function storeOAuth2Vul(oauth2vul) {
    var vul = oauth2vul;
    var RPDomain = vul.RPDomain;
    try {

        var identifiedVuls = JSON.parse(localStorage.getItem(RPDomain + ":vul"));

        if (vul.cookieLeak && identifiedVuls) {
            // deal with cookie leakage vulnerability
            var store = true;
            for (var i = 0; i < identifiedVuls.length; i++) {
                if (vul.IdP == identifiedVuls[i].IdP && identifiedVuls[i].cookieLeak) {
                    console.log("A cookie leakage Vul IdP: " + vul.IdP + " RP: " + vul.RP + "has been identified before!");
                    store = false;
                }
            }
            if (store) {
                identifiedVuls.push(vul);
                console.log("A cookie leakage Vul IdP: " + vul.IdP + " RP: " + vul.RP + "has been found and store to local storage!");
                localStorage.setItem(RPDomain + ":vul", JSON.stringify(identifiedVuls));
            }
        } else if (vul.refererLeak && identifiedVuls) {
            identifiedVuls.push(vul);
            console.log("A referer leakage Vul IdP: " + vul.IdP + " RP: " + vul.RP + "has been found and store to local storage!");
            localStorage.setItem(RPDomain + ":vul", JSON.stringify(identifiedVuls));
        } else {
            localStorage.setItem(RPDomain + ":vul", JSON.stringify([vul]));
            console.log("OAuth2.0 vulnerability has been found and writes to localstorage");
        }
    }
    catch (e) {
        console.log(e);
    }
}
/*
 * check whether an OAuth 2 IdP has been stored in the array.
 */
function containsOAuth2(obj, list) {
    var i;
    for (i = 0; i < list.length; i++) {
        if (list[i].IdP === obj.IdP) {
            return true;
        }
    }
    return false;
}

/*
 * returns the vulnerabilities that we can identify from the OAuth 2.0 requests
 * @param {host} the host name
 * @return {RP:IdP} returns a dictionary
 *
 */
function extraceRedirectURLs(host) {
    var rpDomain = extractDomain(host);
    var OAuth2Requests = JSON.parse(localStorage.getItem(rpDomain));
    // console.log(OAuth2Requests);
    var URLs = {};
    var data = {};
    data["origin"] = null;
    if (OAuth2Requests) {
        for (var i = 0; i < OAuth2Requests.length; i++) {
            if (OAuth2Requests[i].redirectURI === "postmessage") {
                URLs[OAuth2Requests[i].IdP] = OAuth2Requests[i].origin;
                data["origin"] = true;
            } else {
                URLs[OAuth2Requests[i].IdP] = OAuth2Requests[i].redirectURI;
                data["origin"] = false;
            }
        }
    }
    data["URLs"] = URLs;
    return data;
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

/*
 * check a string is a code.
 */

function isGoogleCode(str) {
    if (str) {
        uri_dec = decodeURIComponent(str);
        var pattern = new RegExp('4/\..{43}');
        return pattern.exec(uri_dec);
    }
}

/*›
 * check a string is an ID token.
 */

function isGoogleIDToken(str) {
    if (str) {
        uri_dec = decodeURIComponent(str);
        var pattern = new RegExp('eyJ.*\.eyJ.*\..{342}');
        return pattern.exec(uri_dec);
    }
}

/*
 * check a string is an access token.
 */

function isGoogleAccessToken(str) {
    if (str) {
        uri_dec = decodeURIComponent(str);
        var pattern = new RegExp('ya29\..{124,130}');
        return pattern.exec(uri_dec);
    }
}

function extraceRedirectURLs(host) {
    var rpDomain = extractDomain(host);
    var OAuth2Requests = JSON.parse(localStorage.getItem(rpDomain));
    // console.log(OAuth2Requests);
    var URLs = {};
    var data = {};
    data["origin"] = null;
    if (OAuth2Requests) {
        for (var i = 0; i < OAuth2Requests.length; i++) {
            if (OAuth2Requests[i].redirectURI === "postmessage") {
                URLs[OAuth2Requests[i].IdP] = OAuth2Requests[i].origin;
                data["origin"] = true;
            } else {
                URLs[OAuth2Requests[i].IdP] = OAuth2Requests[i].redirectURI;
                data["origin"] = false;
            }
        }
    }
    data["URLs"] = URLs;
    return data;
}


