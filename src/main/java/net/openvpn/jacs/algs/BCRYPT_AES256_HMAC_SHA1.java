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

package net.openvpn.jacs.algs;

import net.openvpn.jacs.*;

/**
 * Crypto parameters for BCRYPT + AES-256 + HMAC-SHA-1 signature.
 */
public class BCRYPT_AES256_HMAC_SHA1 extends BCRYPT_AES256_HMAC_SHA256 {
	@Override
	public String name() {
		return "BCRYPT-AES256-HMAC-SHA1";
	}

	@Override
	public CipherMacSpec create() {
		return new BCRYPT_AES256_HMAC_SHA1();
	}

	protected String hmacAlg() {
		return "HmacSHA1";
	}
}
