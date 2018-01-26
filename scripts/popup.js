// create the report page
function checkResult(){
    chrome.tabs.create({url: chrome.extension.getURL("contents/report.html"), active:false}, function(tab){
        console.log("New tabs was crated!!!!");
    });
}

function openToolsPanel(){
    chrome.tabs.create({url: chrome.extension.getURL("contents/analyse.html"), active:false}, function(tab){
        console.log("New tabs was crated!!!!");
    });
}

function openVulDiscrpitonPanel(){
    chrome.tabs.create({url: chrome.extension.getURL("contents/vulnerabilities.html"), active:false}, function(tab){
        console.log("New tabs was crated!!!!");
    });
}

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

function createWarnings() {
    // body...
    var RPDomains = Object.keys(localStorage);
    var whitelistItems = ["https-upgrade", "HTTPSUpgradeCounter", "CSRFCounter", "thirdPartyTokenLeaksCounter", "refererLeakageCounter", "privacy", "refererLeakage"]
    var impersonationAttackRPs = [];
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
            var OAuthResponse = OAuthResponses[0];
            var threats = detectOAuth2Threats(OAuthRequest, OAuthResponse);
            var threatsTypes = Object.keys(threats);
            if (threatsTypes.length > 0 && threatsTypes.indexOf("impersonationAttack") >= 0){
                impersonationAttackRPs.push(RPDomain);
            }
        }
    }
    if(impersonationAttackRPs.length > 0){
        return impersonationAttackRPs;
    }else{
        return null;
    }
}


// export collected data
function exportData() {
    // body...
    var data = {};
    var urls = Object.keys(localStorage);
    for (var i = 0; i < urls.length; i++) {
        var value = localStorage.getItem(urls[i]);
        // preserve newlines, etc - use valid JSON
        // console.log(typeof(JSON.parse(value)));
        data[urls[i]] = JSON.parse(value);
    }
    chrome.downloads.download({
        url: "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data)),
        filename: "data.json",
        conflictAction: "uniquify", // or "overwrite" / "prompt"
        saveAs: false, // true gives save-as dialogue
    }, function(downloadId) {
        console.log("Downloaded item with ID", downloadId);
    });
}

function getCounter(threatName) {
    var counterName = threatName+'Counter';
    var blockingCount = localStorage.getItem(counterName);
    if (blockingCount) {
        blockingCount = parseInt(blockingCount);
        return blockingCount;
    }else{
        return 0;
    }
}

// document.getElementById("check-report").onclick = checkResult;

document.addEventListener('DOMContentLoaded', function () {

    var button = document.getElementById("check-report");
    if (button){
        document.getElementById("check-report").onclick = checkResult;
    }
    document.getElementById("open-tools").onclick = openToolsPanel;
    document.getElementById("vulnerabilities").onclick = openVulDiscrpitonPanel;
    var exp = document.getElementById("export-data");
    if (exp) {
        document.getElementById("export-data").onclick = exportData;
    }

    // get counters
    document.getElementById("csrf-attack").innerHTML = getCounter("CSRF");
    document.getElementById("third-party-leak").innerHTML = getCounter("thirdPartyTokenLeaks");
    document.getElementById("referer-leak").innerHTML = getCounter("refererLeakage");
    document.getElementById("https-upgrade").innerHTML = getCounter("HTTPSUpgrade");
    document.getElementById("oauthguard-board").childNodes[0].style.color = "red";

    // set up https options
    var isHTTPS = localStorage.getItem("https-options");
    if (parseInt(isHTTPS)) {
        document.getElementById("https-options").innerHTML = "Turn off HTTPS Upgrade";
    }else{
        document.getElementById("https-options").innerHTML = "Turn on HTTPS Upgrade";
    }

    document.getElementById("https-options").onclick = function() {
        var isHTTPSUpgrade = localStorage.getItem("https-options");
        if (parseInt(isHTTPSUpgrade)) {
            localStorage.setItem("https-options", 0);
            document.getElementById("https-options").innerHTML = "Turn on HTTPS Upgrade";
        }else{
            localStorage.setItem("https-options", 1);
            document.getElementById("https-options").innerHTML = "Turn off HTTPS Upgrade";
        }

    };

    // get warnings
    var warningsDiv = document.getElementById("guard-warnings");
    var warnings = createWarnings();
    if (warnings) {
        var warningRPs = warnings.length;
        var listNumbers = 3;
        console.log(warnings)
        var lines = parseInt(warningRPs/listNumbers);
        var reminder = warningRPs % listNumbers;
        for (var i = 0; i < 3; i++) {
            var ul = document.createElement('ul');
            for (var j = 0; j <= lines; j++) {
                var RPDomain = warnings[j * 3 + i];
                if (!RPDomain) {
                    continue;
                }
                var li = document.createElement('li');
                var a = document.createElement('a');
                a.setAttribute("class", "warning-domain");
                a.setAttribute("href", "http://"+RPDomain);
                a.innerHTML = RPDomain;
                li.appendChild(a);
                ul.appendChild(li);
            }
            warningsDiv.appendChild(ul);
        }
    }



    // set panel css
    document.getElementById("oauthguard-board").childNodes[0].onclick = function() {
        document.getElementById("oauthguard-board").childNodes[0].style.color = "red";
        document.getElementById("oauthguard-warnings").childNodes[0].style.color = "#2b2b2b";
        document.getElementById("oauthguard-tools").childNodes[0].style.color = "#2b2b2b";
        document.getElementById("guard-warnings").style.display = 'none';
        document.getElementById("guard-board").style.display = "inline-block";
        document.getElementById("guard-tools").style.display = "none";
    };
    document.getElementById("oauthguard-warnings").childNodes[0].onclick = function() {
        document.getElementById("oauthguard-board").childNodes[0].style.color = "#2b2b2b";
        document.getElementById("oauthguard-warnings").childNodes[0].style.color = "red";
        document.getElementById("oauthguard-tools").childNodes[0].style.color = "#2b2b2b";
        document.getElementById("guard-warnings").style.display = 'inline-block';
        document.getElementById("guard-board").style.display = "none";
        document.getElementById("guard-tools").style.display = "none";
    };
    document.getElementById("oauthguard-tools").childNodes[0].onclick = function() {
        document.getElementById("oauthguard-board").childNodes[0].style.color = "#2b2b2b";
        document.getElementById("oauthguard-warnings").childNodes[0].style.color = "#2b2b2b";
        document.getElementById("oauthguard-tools").childNodes[0].style.color = "red";
        document.getElementById("guard-warnings").style.display = "none" ;
        document.getElementById("guard-board").style.display = "none";
        document.getElementById("guard-tools").style.display = "inline-block";
    };
});
