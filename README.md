endecrypt
=========
Password based en-/decryption of arbitrary data with and for node.js.

Features
--------
* Utilizes PBKDF2 and AES256 through [node's crypto module](http://nodejs.org/api/crypto.html) and is therefore pretty fast
* Encrypted outputs are indistinguishable from random data
* Works with arbitrary buffer contents as well as with any form of JSON data (see: Stores)
* Provides simple streaming and one-shot APIs
* Includes handy `encrypt`, `decrypt` and `keystore` command line utilities

API
---
The API is quite simple:

`var endecrypt = require("endecrypt");`

#### One-shot usage for small data:

* ##### endecrypt.encrypt(buf:Buffer, passphrase:string[, options:Object], callback:function(err:Error, data:Buffer))  
  Encrypts the specified buffer with the given passphrase and returns the encrypted binary data.
  
* ##### endecrypt.decrypt(buf:Buffer, passphrase:string[, options:Object], callback:function(err:Error, data:Buffer))  
  Decrypts the specified buffer with the given passphrase and returns the decrypted binary data.
  
* ##### endecrypt.encryptStore(data:*, passphrase:string[, options:Object], callback:function(err:Error, data:Buffer))  
  Encrypts the specified JSON data with the given passphrase and returns the encrypted store data.
  
* ##### endecrypt.decryptStore(buf:Buffer, passphrase:string[, options:Object], callback:function(err:Error, data:*))  
  Decrypts the specified store data with the given passphrase and returns the decrypted JSON data.

#### Streaming usage for possibly large data (generally recommended):

* ##### endecrypt.createEncrypt(passphrase:string[, options:Object]):endecrypt.Encrypt  
  Creates a ready-to-pipe encrypting ([transforming](http://nodejs.org/api/stream.html#stream_class_stream_transform_1)) stream.
  
* ##### endecrypt.createDecrypt(passphrase:string[, options:Object]):endecrypt.Decrypt  
  Creates a ready-to-pipe decrypting ([transforming](http://nodejs.org/api/stream.html#stream_class_stream_transform_1)) stream.
  
#### Available options:  
* **rounds**  
  Number of PBKDF2 (HMAC-SHA1) rounds to perform, defaults to 100000.
    
Command line
------------
Pretty much the same as available through the API, but with the exception that the application will ask for the
passphrase if it is not specified as an argument. The number of PBKDF2 rounds defaults to 100000.

* `encrypt <infile> [-r=ROUNDS] [-p=PASSPHRASE] [> <outfile>]`
* `decrypt <infile> [-r=ROUNDS] [-p=PASSPHRASE] [> <outfile>]`
* `keystore list|add|get|del ...` Run `keystore` for the details

Stores
------
endecrypt provides the tools to en-/decrypt arbitrary JSON data *including* binary buffers and utilizes the
[PSON](https://github.com/dcodeIO/PSON) data format internally for the purpose of converting JSON data to its binary
representation prior to encryption and vice-versa. In endecrypt this is called a store.

Likewise, the `keystore` utility works with one level of nesting, making it effectively a key-value store (plain
object to PSON). A possible use case could be to store a set of private keys and certificates in an endecrypt store to
be able to use a common password once to access all the confidential entries. Unlike with other keystores like JKS
there is no item-level access control mechanism, just a global one.

Using the API it is possible to put any form of JSON data into a store, not just plain objects.

Examples
--------
The file **README.md.crypt** has been generated through `encrypt README.md -p=123 > README.md.crypt` and can be
decrypted using `decrypt README.md.crypt -p=123`.

Considerations
--------------
endecrypt uses node's stock PBKDF2 implementation which uses HMAC-SHA1 to derive keys. Thus, the effective entropy is
160 bits aligned to 256 bits of AES which may change with future versions (i.e. when the guys at node.js implement
SHA256).

**License:** [Apache License, Version 2.0](http://opensource.org/licenses/Apache-2.0)
