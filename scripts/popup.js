// create the report page
function checkResult(){
    chrome.tabs.create({url: chrome.extension.getURL("contents/report.html"), active:false}, function(tab){
        console.log("New tabs was crated!!!!");
    });
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


// document.getElementById("check-report").onclick = checkResult;

document.addEventListener('DOMContentLoaded', function () {
    var button = document.getElementById("check-report");
    if (button){
        document.getElementById("check-report").onclick = checkResult;
    }
    var exp = document.getElementById("export-data");
    if (exp) {
        document.getElementById("export-data").onclick = exportData;
    }
});
