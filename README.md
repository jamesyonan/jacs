Jacs : Java augmented cipher streams
====================================

Jacs is a Java library and command-line tool for encrypting
streams and files using a passphrase, including support
for PBKDF2, SCrypt, BCrypt, AES, Explicit IV, and
HMAC-based integrity checking.

Jacs extends the Java CipherInputStream and CipherOutputStream
classes to support Explicit IV and HMAC integrity checking.

Jacs is integrated with common key derivation algorithms,
including PBKDF2, SCrypt, and BCrypt.

Jacs supports AES out-of-the-box via JCE.  Other cipher
algorithms can easily be added if the Bouncy Castle library is
present.

Classes:

* __CipherOutputStreamIVMAC__ -- Encrypt data to binary, using
the format Explicit IV, ciphertext data, and HMAC signature.

* __CipherInputStreamIVMAC__ -- Decrypt data from binary, using
the format Explicit IV, ciphertext data, and HMAC signature.

* __CipherOutputStreamIVMACBase64__ -- Like CipherOutputStreamIVMAC,
but encrypt to base64.

* __CipherInputStreamIVMACBase64__ -- Like CipherInputStreamIVMAC,
but decrypt to base64.

Key Derivation: PBKDF2, SCrypt, or BCrypt, caller may choose
key derivation algorithm strength

Cipher algorithms: AES-256-CBC with PKCS5 Padding.  Other
algorithms can easily be added if the Bouncy Castle
crypto library is present.

IV: Explicit, never reused, generated from strong PRNG

HMAC: SHA256 (using encrypt-then-MAC approach, where leading
      IV + all ciphertext is signed)

Encrypted stream format:

```
[  16 bytes -- IV ]
[   n bytes -- ciphertext ]
[  32 bytes -- HMAC-SHA256 signature of IV, ciphertext ]
```

Sample Code
-----------

Encrypt:

```java
// outStream is an OutputStream that
// ciphertext (base64) will be written to.
CipherMacSpec spec = JacsAlgs.getInstance("PBKDF2-SHA1-AES256-HMAC-SHA256");
spec.init("mypassword", 16); // 2^16 PBKDF2 iterations
CipherOutputStreamIVMACBase64 cos = new CipherOutputStreamIVMACBase64(outStream, spec);

// You can now write plaintext to cos like a
// CipherOutputStream object.  Don't forget to
// close cos when done, as that triggers the
// writing of the HMAC signature.
```

Decrypt:

```java
// inStream is an InputStream that
// will read ciphertext (base64).
CipherInputStreamIVMACBase64 cis = new CipherInputStreamIVMACBase64(inStream, "mypassword", false);

// You can now read plaintext from cis like
// a CipherInputStream object.  Don't forget
// to close cis when done, as that triggers
// the HMAC signature verification.
```

See src/main/java/net/openvpn/jacs/Jacs.java for a more complete
example that implements the jacs command line tool.

Security discussion
-------------------

Java's CipherInputStream and CipherOutputStream class (from the
JCE) lack two important capabilities:

* Support for using a randomized "Explicit IV" to ensure that
  identical plaintexts encrypt to different ciphertexts even
  when the same key is used.

* Integrity checking when decrypting ciphertext, to ensure that
  the ciphertext was not forged or tampered with (Jacs uses
  encrypt-then-MAC approach, where leading IV + all ciphertext
  is signed).

Both of these capabilities are considered essential to modern
security protocols and are present in [TLS 1.1](http://tools.ietf.org/html/rfc4346) and higher, [ESP](http://tools.ietf.org/html/rfc4303)
(Used in IPSec), and [OpenVPN](http://openvpn.net/index.php/open-source/documentation/security-overview.html).

The Jacs library adds these capabilities via the new classes
CipherInputStreamIVMAC and CipherOutputStreamIVMAC, which are
intended to be drop-in replacements for CipherInputStream and
CipherOutputStream.

When using CipherInputStreamIVMAC and CipherOutputStreamIVMAC, the
encrypted stream format is expanded to include both Explicit IV and
HMAC signature.

For example, when using PBKDF2-SHA1-AES256-HMAC-SHA256,
the stream format is as follows:

```
[  16 bytes -- IV ]
[   n bytes -- ciphertext ]
[  32 bytes -- HMAC-SHA256 signature of IV, ciphertext ]
```

The Jacs library generates encryption keys from a user-supplied
passphrase, using one of several key derivation or "key-stretching"
algorithms.  Using a key derivation algorithm with a sufficiently
high iteration count is essential when deriving encryption keys
from user-supplied passphrases, as most users are incapable of
remembering a password with sufficient entropy to foil modern
password cracking schemes.

Jacs supports the following key derivation algorithms:

1. __PBKDF2-SHA1__ -- [A NIST standard][1], also published as an
   [Internet Standard (RFC 2898)][2].

   Pros: Developed by RSA labs, well-researched and standardized.

   Cons: Modern password cracking methods using off-the-shelf
   GPU hardware can brute force SHA1-hashed passwords at the
   rate of [2.3 billion per second][3].

2. __PBKDF2-SHA512__ -- While not standardized, this algorithm is
   identical to PBKDF2-SHA1, except that SHA512 is used in
   place of SHA1.

   Pros: SHA512 is more difficult than SHA1 for an attacker
   to accelerate with off-the-shelf GPU hardware because it
   relies extensively on 64-bit integer operations.

   Cons: not officially standardized.

3. [__Bcrypt__][4] -- Uses a variation of the Blowfish cipher algorithm
   to derive keys.

   Pros: actively used since 1999 without known vulnerabilities.
   Less amenable to GPU acceleration due to memory requirements.

   Cons: not officially standardized, lacks the depth of security
   analysis that has gone into PBKDF2-SHA1.

4. [__Scrypt__][5] -- Intentionally designed to be resource-intensive both
   in memory requirements and computational complexity, to thwart
   attempts by attackers to accelerate the algorithm using GPUs
   or specialized hardware such as ASICs or FPGAs.  Scrypt is
   published as an [internet draft][6].

   Pros: Difficult or impossible for an attacker to accelerate using
   GPUs or specialized hardware, no known vulnerabilities.

   Cons: Scrypt is a recent algorithm, first presented in 2009, and
   has less of a track-record than other algorithms in common use.
   Like Bcrypt, it also lacks the depth of security analysis that
   has gone into PBKDF2-SHA1.

[1]: http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf

[2]: http://www.ietf.org/rfc/rfc2898.txt

[3]: http://www.golubev.com/hashgpu.htm

[4]: http://www.usenix.org/events/usenix99/provos/provos_html/node1.html

[5]: http://www.tarsnap.com/scrypt/scrypt.pdf

[6]: http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01

Jacs implementation notes:

Because Jacs provides integrity checking via HMAC, the key derivation
methods used to generate a key from a passphrase must actually
generate two keys: one for the cipher key and one for the HMAC key.
These are the methods used by Jacs to generate these keys for each
key derivation method:

1. __PBKDF2-SHA1__: two distinct constant salts (16 bytes each) are used
   with the PBKDF2-SHA1 algorithm to transform the passphrase into
   the cipher key and HMAC key.  The iteration count is taken as 2^_S_
   where _S_ is the "strength" parameter provided by the user.

2. __PBKDF2-SHA512__: a single 32 byte constant salt and passphrase are
   used as input to the PBKDF2-SHA512 algorithm to derive a 512 bit
   key.  The PBKDF2-SHA512 algorithm is implemented identically to
   PBKDF2-SHA1, except SHA512 is used as the hashing algorithm.
   The 512 bit key produced by PBKDF2-SHA512 is then split into two
   256 bit keys to be used as cipher and HMAC keys.  Like
   PBKDF2-SHA1 above, the iteration count is taken as 2^_S_ where _S_ is
   the "strength" parameter provided by the user.

3. __Bcrypt__: a single 32 byte constant salt and passphrase are used to
   derive a 24-byte key using the Bcrypt algorithm, which is then
   expanded to 64 bytes using one round of SHA512.  The resulting
   key is then split into two 32-byte keys to be used as cipher and
   HMAC keys.  The "strength" parameter provided by the user is passed
   to the Bcrypt algorithm as the "log_rounds" parameter.

4. __Scrypt__: a single 32 byte constant salt and passphrase are used by
   SCrypt to derive a 64-byte key, which is then split into two
   32-byte keys to be used as cipher and HMAC keys.  Scrypt
   parameters are set as follows:

   _N_ -- CPU cost parameter : set to 2^_S_ where _S_ is the "strength"
   parameter provided by the user.

   _r_ -- memory cost parameter : set to 8

   _p_ -- parallelization parameter : set to 1

PRNG and entropy:

* For encryption, a random IV is automatically generated by the
  Java Cipher.init method and is accessed using Cipher.getIV()
  member.

* All constant salts used in Jacs were generated from /dev/urandom

Validation:

To validate the correctness of the Java/JCE code used in the
PBKDF2-SHA1-AES256-HMAC-SHA256 implementation, an alternative
implementation supporting key derivation and decryption is
provided using C/OpenSSL in test/dec.c.  The automated test
script (test/go) verifies the consistency of plaintext
encrypted with Jacs and decrypted using the C/OpenSSL code.

Jacs also includes standard junit-based unit tests,
which are provided for Jacs, PBKDF2, SCrypt, and BCrypt.
The test/go script also verifies the junit tests.

Sources:

* Bcrypt implementation -- Damien Miller
  https://github.com/jeremyh/jBCrypt

* Scrypt and PBKDF2 implementations -- Will Glozer
  https://github.com/wg/scrypt

Build and test for unix (requires maven)
----------------------------------------

    $ ./build

Standalone executable will be written to ./jacs

````
$ ./jacs
jacs 0.5.1: symmetric encryption tool
usage:
  encrypt : jacs E <alg> <password> <strength> <infile> <outfile>
  decrypt : jacs D <alg> <password> <strength> <infile> <outfile>
  encrypt to base64   : jacs E64 <alg> <password> <strength> <infile> <outfile>
  decrypt from base64 : jacs D64[A] <password> <infile> <outfile>
algs: 
  PBKDF2-SHA1-AES256-HMAC-SHA256
  PBKDF2-SHA512-AES256-HMAC-SHA256
  SCRYPT-AES256-HMAC-SHA256
  BCRYPT-AES256-HMAC-SHA256
password   : password or '.' to prompt from stdin without echo
strength   : strength of password derivation (1 to 32)
infile     : input pathname or 'stdin'
outfile    : output pathname or 'stdout'
'A' suffix : for D64, pass through input if not encrypted
````

Testing and validation
----------------------

To run test suite:

    $ test/go

Note that the test suite not only verifies consistency of the
Jacs library, but also verifies decryption using a C/OpenSSL
tool instead of one based on Java/JCE to verify the consistency
of Jacs encryption file format using an alternative implementation.
