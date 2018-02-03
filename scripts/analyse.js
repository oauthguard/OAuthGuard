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

function insertToTable(table, attr, value) {
    var table = document.getElementById(table);
    var row = table.insertRow(-1);
    var cell1 = row.insertCell(0);
    var cell2 = row.insertCell(1);
    // Add some text to the new cells:
    cell1.innerHTML = attr;
    cell2.innerHTML = value;
    // body...
}

function createTable(name) {
    var h = document.createElement("H1");
    h.setAttribute("id", name +'-header');
    var t = document.createTextNode("OAuth2.0 " + name);
    h.appendChild(t);
    document.body.appendChild(h);
    var table = document.createElement("TABLE");
    table.setAttribute("id", name + "-table");
    table.setAttribute("class", "container");
    var th0 = document.createElement("TH");
    var th1 = document.createElement("TH");
    var text0 = document.createTextNode("Attribute");
    var text1 = document.createTextNode("Value");
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

document.addEventListener('DOMContentLoaded', function () {
    var button = document.getElementById("check-RP");
    if (button){
        button.onclick = checkRP;
    }
    var clear = document.getElementById("clear-records");
    if (clear){
        clear.onclick = clearTable;
    }

});




