/*
 * Copyright (C) 2013 OpenVPN Technologies, Inc.
 *
 * Author: James Yonan <james@openvpn.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Jacs -- Java augmented cipher streams.
 * See README.txt for more info.
 */

package net.openvpn.jacs;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.security.NoSuchAlgorithmException;
import java.security.GeneralSecurityException;
import java.security.spec.InvalidKeySpecException;
import java.io.UnsupportedEncodingException;

/**
 * Base class for specifying a Cipher/Mac pair.  Derived classes
 * should initialize cipher, cipherKey, mac, and macKey in their
 * constructors.
 *
 * See algs directory for derivatives of this class.
 *
 * Once a CipherMacSpec is generated, it can then be passed to
 * CipherInputStreamIVMAC, CipherOutputStreamIVMAC, or
 * CipherOutputStreamIVMACBase64.  These classes
 * are drop-in replacements for CipherInputStream and
 * CipherOutputStream that add support for Explicit IV and HMAC
 * integrity checking as well as base64-format output.
 */
public abstract class CipherMacSpec {
	protected Cipher cipher;
	protected SecretKeySpec cipherKey;
	protected Mac mac;
	protected SecretKeySpec macKey;

	/**
	 * Algorithm name.
	 *
	 * @return The algorithm name
	 */
	abstract public String name();

	/**
	 * Algorithm Key derivation complexity.
	 * Range is 1 to 31.  Each higher increment
	 * doubles computational complexity.
	 *
	 * @return The key derivation complexity that was
	 *         passed as strength value to init()
	 */
	abstract public int strength();

	/**
	 * Is the algorithm available?
	 *
	 * @return True if this algorithm is available.
	 */
	abstract public boolean available();

	/**
	 * Create a new uninitialized instance of this object.
	 *
	 * @return A new, uninitialized CipherMacSpec instance
	 *         of the same class as this object.
	 */
	abstract public CipherMacSpec create();

	/**
	 * Get key size.
	 *
	 * @return Combined Cipher/HMAC key size in bytes.
	 */
	abstract public int keySize();

	/**
	 * Initialize a CipherMacSpec object with password and
	 * key derivation complexity.
	 *
	 * Individual algs should override this method
	 * to initialize cipher, cipherKey, mac, and macKey.
	 *
	 * @param password Password used to derive cipher and HMAC keys.
	 * @param strength Key derivation complexity.
	 */
	abstract public void init(String password, int strength)
		throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, GeneralSecurityException;

	/**
	 * Initialize a CipherMacSpec object with byte[] key.
	 * Caller should use keySize() to get the required key size.
	 *
	 * Individual algs should override this method
	 * to initialize cipher, cipherKey, mac, and macKey.
	 *
	 * @param key Combined key for cipher and HMAC keys.
	 */
	abstract public void init(byte[] key)
		throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, GeneralSecurityException;

	/**
	 * Initialize a CipherMacSpec object with
	 * separate keys for cipher and mac.
	 *
	 * Individual algs should override this method
	 * to initialize cipher, cipherKey, mac, and macKey.
	 *
	 * @param cipherKey Cipher key.
	 * @param macKey HMAC key.
	 */
	abstract public void init(SecretKeySpec cipherKey, SecretKeySpec macKey)
		throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, GeneralSecurityException;
}
