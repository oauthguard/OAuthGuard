function checkRP() {
    // body...
    var RPDomain = document.getElementById('rp_to_check').value;
    if (RPDomain) {
        var OAuth2Recrods = localStorage.getItem(RPDomain);
        if (OAuth2Recrods) {
            OAuth2Recrods = JSON.parse(OAuth2Recrods);
            var request = OAuth2Recrods.request;
            var response = OAuth2Recrods.response;
            var requestAttributes = Object.keys(request);
            createTable('request');
            for (var i = 0; i < requestAttributes.length; i++) {
                var attr = requestAttributes[i];
                var value = request[attr];
                if (value) {
                    insertToTable('request-table', attr, value);
                }
            }

            var responseAttributes = Object.keys(response[0]);
            createTable('response');
            for (var i = 0; i < responseAttributes.length; i++) {
                var attr = responseAttributes[i];
                var value = response[0][attr];
                if (value) {
                    insertToTable('response-table', attr, value);
                }

            }
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
        // referer header is present in the response
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
                    if (redirect_uri === 'postmessage') {
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
        }
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


function printThreats(threats) {
    var threatNames = Object.keys(threats);
    var msg = ''
    if (threatNames.length > 0) {
        for (let i = 0; i < threatNames.length; i++) {
            const threatName = threatNames[i];
            msg += threatName + ';';
        }
        return msg;
    }

}


function generateReport() {
    var RPDomains = Object.keys(localStorage);
    var whitelistItems = ["HTTPSUpgradeCounter", "CSRFCounter", "thirdPartyTokenLeaksCounter", "refererLeakageCounter", "privacy", "refererLeakage"]
    var counterNumber = 0;
    for (var i = 0; i < RPDomains.length; i++) {
        var RPDomain = RPDomains[i];
        if (whitelistItems.indexOf(RPDomain) >= 0) {
            // ignore specific keys.
            continue;
        }else{
            // build tables for each domain;
            var RPRecords = JSON.parse(localStorage.getItem(RPDomain));
            // console.log(RPRecords)
            var OAuthRequest = RPRecords.request;
            var OAuthResponses = RPRecords.response;
            if (!OAuthResponses){
                continue;
            }

            for (var j = 0; j < OAuthResponses.length; j++) {
                console.log("here")
                var OAuthResponse = OAuthResponses[j];
                var threats = detectOAuth2Threats(OAuthRequest, OAuthResponse);
                if (Object.keys(threats).length > 0) {
                    // console.log(threats);
                    var RPTable = document.getElementById(RPDomain+"-table");
                    if (RPTable) {
                        // insert to existing table.
                        insertToTable(RPDomain + "-table", "Response " + (j+1), printThreats(threats));
                    }else{
                        // create a new table.
                        createTable(RPDomain);
                        counterNumber +=1;
                        insertToTable(RPDomain + "-table", "Response " + (j+1), printThreats(threats));
                    }
                }
            }
        }
    }
    console.log(counterNumber + " websites are vulnerable to at least one threat!");

    // body...
}

function insertToTable(table, attr, value) {
    var table = document.getElementById(table);
    var row = table.insertRow(-1);
    var cell1 = row.insertCell(0);
    cell1.setAttribute('class', "response")
    var cell2 = row.insertCell(1);
    // Add some text to the new cells:
    cell1.innerHTML = attr;
    cell2.innerHTML = value;
    // body...
}

function createTable(name) {
    var h = document.createElement("H2");
    h.setAttribute("id", name +'-header');
    var t = document.createTextNode("OAuth2.0 threats report for ");
    var aTag = document.createElement("a");
    aTag.setAttribute('href',"http://"+name);
    aTag.innerHTML = name;

    h.appendChild(t);
    h.appendChild(aTag);
    document.body.appendChild(h);
    var table = document.createElement("TABLE");
    table.setAttribute("id", name + "-table");
    table.setAttribute("class", "container");
    var th0 = document.createElement("TH");
    th0.setAttribute('class', "response");
    var th1 = document.createElement("TH");
    var text0 = document.createTextNode("Repsonse No.");
    var text1 = document.createTextNode("Threats");
    th0.appendChild(text0);
    th1.appendChild(text1);
    table.appendChild(th0);
    table.appendChild(th1);
    document.body.appendChild(table);
}

function clearTable() {
    // body...
    var elements = ['request-table', 'response-table', 'request-header', 'response-header']
    for (var i = 0; i < elements.length; i++) {
        var id = elements[i];
        var elem = document.getElementById(id);
        elem.parentNode.removeChild(elem);
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



document.addEventListener('DOMContentLoaded', function () {
    generateReport();
});




