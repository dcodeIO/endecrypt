/*
 Copyright 2013 Daniel Wirtz <dcode@dcode.io>

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

var crypto = require("crypto"),
    stream = require("stream"),
    util   = require("util");

/**
 * endecrypt namespace.
 * @type {Object.<string.*>}
 */
var endecrypt = {};

/**
 * Salt length.
 * @type {number}
 * @const
 */
endecrypt.SALT_LENGTH = 128/8;

/**
 * Default number of PBKDF2 rounds.
 * @type {number}
 * @const
 */
endecrypt.DEFAULT_ROUNDS = 100000;

/**
 * Prepares the endecrypt options.
 * @param {*} options Given options
 * @returns {{rounds: number}} Prepared options
 * @private
 */
function mkopt(options) {
    options = options || {};
    options.rounds = options.rounds || endecrypt.DEFAULT_ROUNDS;
    return options;
}

/**
 * Constructs a new encrypt stream.
 * @param {string} passphrase Passphrase
 * @param {Object.<string,*>=} options Options
 * @constructor
 * @extends stream.Transform
 */
var Encrypt = function(passphrase, options) {
    stream.Transform.call(this);
    this.options = mkopt(options);
    this.passphrase = passphrase;
    this.cipher = null;
};

// Extends stream.Transform
util.inherits(Encrypt, stream.Transform);

/**
 * Transforms / encrypts the next chunk.
 * @param {Buffer|string} chunk Next chunk
 * @param {string} encoding Encoding if chunk is a string
 * @param {function()} done Callback
 * @private
 */
Encrypt.prototype._transform = function(chunk, encoding, done) {
    if (!Buffer.isBuffer(chunk)) {
        chunk = new Buffer(chunk, encoding);
    }
    if (this.cipher === null) { // Initialize
        crypto.randomBytes(endecrypt.SALT_LENGTH, function(err, salt) {
            if (err) {
                throw(err);
            }
            crypto.pbkdf2(this.passphrase, salt, this.options.rounds, 48, function(err, keyiv) {
                if (err) {
                    throw(err);
                }
                this.passphrase = null;
                this.cipher = crypto.createCipheriv("aes256", keyiv.slice(0, 32), keyiv.slice(32));
                this.push(salt);
                this.push(this.cipher.update(chunk));
                done();
            }.bind(this));
        }.bind(this));
    } else {
        this.push(this.cipher.update(chunk));
        done();
    }
};

/**
 * Flushes all remaining data.
 * @param {function()} done Callback
 * @private
 */
Encrypt.prototype._flush = function(done) {
    if (this.cipher !== null) {
        this.push(this.cipher.final());
    }
    done();
};

endecrypt.Encrypt = Encrypt;

/**
 * Creates a new encrypt stream.
 * @param {string} passphrase Passphrase
 * @param {Object.<string,*>=} options Options
 * @returns {endecrypt.Encrypt}
 */
endecrypt.createEncrypt = function(passphrase, options) {
    return new endecrypt.Encrypt(passphrase, options);
};

/**
 * Constrcuts a new decrypt stream.
 * @param {string} passphrase Passphrase
 * @param {Object.<string,*>=} options Options
 * @constructor
 * @extends stream.Transform
 */
var Decrypt = function(passphrase, options) {
    stream.Transform.call(this);
    this.salt = new Buffer(0);
    this.passphrase = passphrase;
    this.options = mkopt(options);
    this.cipher = null;
};

// Extends stream.Transform
util.inherits(Decrypt, stream.Transform);

/**
 * Gathers additional salt bytes.
 * @param {Buffer} chunk Next chunk
 * @returns {Buffer} Remaining data or NULL if not yet enough
 * @private
 */
Decrypt.prototype._gather = function(chunk) {
    var remain = endecrypt.SALT_LENGTH - this.salt.length;
    if (chunk.length < remain) { // Append additional salt bytes
        this.salt = Buffer.concat([this.salt, chunk]);
        return null;
    }
    // Else fill salt and set up cipher
    this.salt = Buffer.concat([this.salt, chunk.slice(0, remain)]);
    return chunk.slice(remain);
};

/**
 * Transforms / decrypts the next chunk.
 * @param {Buffer|string} chunk Next chunk
 * @param {string} encoding Encoding if chunk is a string
 * @param {function()} done Callback
 * @private
 */
Decrypt.prototype._transform = function(chunk, encoding, done) {
    if (!Buffer.isBuffer(chunk)) {
        chunk = new Buffer(chunk, encoding);
    }
    if (this.salt.length < endecrypt.SALT_LENGTH) {
        if ((chunk = this._gather(chunk)) === null) {
            done(); return;
        }
    }
    if (this.cipher === null) { // Set up
        // FIXME: node's crypto module uses HMAC-SHA1 so deriving a 256 bit key and 128 bit iv is suboptimal. However,
        // a plain JavaScript implementation would be much slower and a C module would need a compile step. Any ideas?
        crypto.pbkdf2(this.passphrase, this.salt, this.options.rounds, 48, function(err, keyiv) {
            if (err) {
                throw(err);
            }
            this.cipher = crypto.createDecipheriv("aes256", keyiv.slice(0, 32), keyiv.slice(32));
            this.push(this.cipher.update(chunk));
            done();
        }.bind(this));
    } else {
        this.push(this.cipher.update(chunk));
        done();
    }
};

/**
 * Flushes all remaining data.
 * @param {function()} done Callback
 * @private
 */
Decrypt.prototype._flush = function(done) {
    if (this.cipher !== null) {
        this.push(this.cipher.final());
    }
    done();
};

/**
 * @alias {Decrypt}
 */
endecrypt.Decrypt = Decrypt;

/**
 * Creates a new decrypt stream.
 * @param {string} passphrase Passphrase
 * @param {Object.<string,*>} options Options
 * @returns {endecrypt.Decrypt}
 */
endecrypt.createDecrypt = function(passphrase, options) {
    return new endecrypt.Decrypt(passphrase, options);
};

/**
 * Encrypts a buffer using the specified passphrase.
 * This is a convenience wrapper around a proper stream and should not be used with large data.
 * @param {Buffer} buf Buffer to encrypt
 * @param {string} passphrase Passphrase
 * @param {Object.<string,*>|function(Error, Buffer=)} options Options
 * @param {function(Error, Buffer=)=} callback Callback
 */
endecrypt.encrypt = function(buf, passphrase, options, callback) {
    if (typeof options === 'function') {
        callback = options;
        options = null;
    }
    var enc = endecrypt.createEncrypt(passphrase, options);
    var out = [];
    enc.on("data", function(chunk) {
        out.push(chunk);
    });
    enc.on("end", function() {
        callback(null, Buffer.concat(out));
    });
    enc.on("error", function(err) {
        callback(err);
    });
    enc.end(buf);
};

/**
 * Decrypts a buffer using the specified passphrase.
 * This is a convenience wrapper around a proper stream and should not be used with large data.
 * @param {Buffer} buf Buffer to decrypt
 * @param {string} passphrase Passphrase
 * @param {Object.<string,*>|function(Error, Buffer=)} options Options
 * @param {function(Error, Buffer=)=} callback Callback
 */
endecrypt.decrypt = function(buf, passphrase, options, callback) {
    if (typeof options === 'function') {
        callback = options;
        options = null;
    }
    var dec = endecrypt.createDecrypt(passphrase, options);
    var out = [];
    dec.on("data", function(chunk) {
        out.push(chunk);
    });
    dec.on("end", function() {
        callback(null, Buffer.concat(out));
    });
    dec.on("error", function(err) {
        callback(err);
    });
    dec.end(buf);
};

module.exports = endecrypt;
