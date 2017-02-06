var tty = require("tty"),
    keypress = require("keypress");

var util = {};

util.setRawMode = function(mode) {
    if (process.stdin.setRawMode) {
        process.stdin.setRawMode(mode);
    } else if (process.stdin.isTTY) {
        tty.setRawMode(mode);
    }
};

util.passphrase = function(prompt, callback) {
    process.stderr.write(prompt);
    keypress(process.stdin);
    process.stdin.resume();
    var passphrase = "";
    process.stdin.on("keypress", function(c, key) {
        if (key && (key.name == "return" || key.name == "enter")) {
            process.stderr.write("\n");
            process.stdin.pause();
            callback(passphrase);
        } else if (key && key.name == "backspace") {
            if (passphrase.length > 0) {
                passphrase = passphrase.substring(0, passphrase.length-1);
                process.stderr.write('\x1B[D\x1B[K');
            }
        } else if (key && key.ctrl && key.name == "u") {
            process.stderr.write(passphrase.replace(/./g, '\x1B[D'));
            passphrase = "";
        } else if (key && key.ctrl && key.name == "c") {
            process.stdin.pause();
            callback(null);
        } else {
            process.stderr.write("*");
            passphrase += c;
        }
    });
};

module.exports = util;
