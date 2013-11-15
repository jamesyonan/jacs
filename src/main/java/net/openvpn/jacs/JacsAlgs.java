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

import java.util.ArrayList;
import java.io.IOException;

import net.openvpn.jacs.algs.*;

/**
 * Methods to enumerate available algorithms and get
 * instances of specific algorithms.
 */
public class JacsAlgs {
	public static class NotFound extends IOException {
		public NotFound(String alg) {
			super("Jacs algorithm not found: " + alg);
		}
	}

	private static CipherMacSpec[] algs = new CipherMacSpec[] {
		new PBKDF2_SHA1_AES256_HMAC_SHA256(),
		new PBKDF2_SHA512_AES256_HMAC_SHA256(),
		new SCRYPT_AES256_HMAC_SHA256(),
		new BCRYPT_AES256_HMAC_SHA256(),
		new PBKDF2_SHA1_AES256_HMAC_SHA1(),
		new PBKDF2_SHA512_AES256_HMAC_SHA1(),
		new SCRYPT_AES256_HMAC_SHA1(),
		new BCRYPT_AES256_HMAC_SHA1(),
	};

	/**
	 * Get an uninitialized instance of a CipherMacSpec.
	 * Caller must call init() method before object is
	 * passed to CipherInputStreamIVMAC, CipherOutputStreamIVMAC,
	 * or CipherOutputStreamIVMACBase64.
	 *
	 * @param name Algorithm name.
	 * @return An uninitialized CipherMacSpec instance.
	 */
	public static CipherMacSpec getInstance(String name) {
		for (CipherMacSpec cms : algs) {
			if (name.equals(cms.name()) && cms.available())
				return cms.create();
		}
		return null;
	}

	/**
	 * Enumerate available encryption/decryption algorithms.
	 *
	 * @return An array of available algorithm names.
	 */
	public static String[] enumAlgs() {
		ArrayList<String> list = new ArrayList<String>();
		for (CipherMacSpec cms : algs) {
			if (cms.available())
				list.add(cms.name());
		}
		return (String[])list.toArray(new String[list.size()]);
	}
}
