endecrypt
=========
Password based en-/decryption of arbitrary data with and for node.js.

Features
--------
* Uses [node's crypto module](http://nodejs.org/api/crypto.html) and is therefore pretty fast
* Encrypted outputs are indistinguishable from random data
* Works with arbitrary buffer contents
* Provides simple streaming and one-shot APIs
* Includes handy `encrypt` and `decrypt` command line utilities

API
---
The API is quite simple:

`var endecrypt = require("endecrypt");`

### One-shot usage for small data:

* ##### endecrypt.encrypt(buf:Buffer, passphrase:string[, options:Object], callback:function(err:Error, data:Buffer))  
  Encrypts the specified buffer with the given passphrase and returns the result
  
* ##### endecrypt.decrypt(buf:Buffer, passphrase:string[, options:Object], callback:function(err:Error, data:Buffer))  
  Decrypts the specified buffer with the given passphrase and returns the result
    
### Streaming usage for possibly large data (generally recommended):

* ##### endecrypt.createEncrypt(passphrase:string[, options:Object]):endecrypt.Encrypt  
  Creates a ready-to-pipe encrypting ([transforming](http://nodejs.org/api/stream.html#stream_class_stream_transform_1)) stream.
  
* ##### endecrypt.createDecrypt(passphrase:string[, options:Object]):endecrypt.Decrypt  
  Creates a ready-to-pipe decrypting ([transforming](http://nodejs.org/api/stream.html#stream_class_stream_transform_1)) stream.
  
#### Available options:  
* ##### rounds    
  Number of PBKDF2 (HMAC-SHA1) rounds to perform, defaults to 100000.
    
Command line
------------
Pretty much the same as available through the API, but with the exception that the application will ask for the
passphrase if it is not specified as an argument. The number of PBKDF2 rounds defaults to 100000.

* `encrypt <infile> [-r=ROUNDS] [-p=PASSPHRASE] [> <outfile>]`
* `decrypt <infile> [-r=ROUNDS] [-p=PASSPHRASE] [> <outfile>]`

That's pretty much it.

Considerations
--------------
endecrypt uses node's stock PBKDF2 implementation which uses HMAC-SHA1 to derive keys. Thus, the effective entropy is
160 bits aligned to 256 bits of AES which may change with future versions (i.e. when the guys at node.js implement
SHA256).

**License:** [Apache License, Version 2.0](http://opensource.org/licenses/Apache-2.0)
