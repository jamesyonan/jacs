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

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.NoSuchPaddingException;
import java.security.GeneralSecurityException;
import java.io.UnsupportedEncodingException;

/**
 * Crypto parameters for PBKDF2-SHA1 + AES-256 + HMAC-SHA-256 signature.
 */
public class PBKDF2_SHA512_AES256_HMAC_SHA256 extends CipherMacSpec {
	protected int kdstrength = -1;

	@Override
	public String name() {
		return "PBKDF2-SHA512-AES256-HMAC-SHA256";
	}

	@Override
	public CipherMacSpec create() {
		return new PBKDF2_SHA512_AES256_HMAC_SHA256();
	}

	protected String pbkdf2HmacAlg() {
		return "HmacSHA512";
	}

	protected String cipherAlg() {
		return "AES/CBC/PKCS5Padding";
	}

	protected String cipherFamily() {
		return "AES";
	}

	protected int cipherKeySize() {
		return 256;
	}

	protected String hmacAlg() {
		return "HmacSHA256";
	}

	protected int hmacKeySize() {
		return 256;
	}
	protected byte[] salt() {
		return new byte[] {
			(byte)0x38, (byte)0xab, (byte)0x63, (byte)0x7f,
			(byte)0xa4, (byte)0x6e, (byte)0x53, (byte)0xf1,
			(byte)0x8a, (byte)0xd3, (byte)0x2c, (byte)0x4e,
			(byte)0xc9, (byte)0x72, (byte)0x5e, (byte)0xf8,
			(byte)0xc5, (byte)0x72, (byte)0xee, (byte)0x51,
			(byte)0xb3, (byte)0x93, (byte)0xa8, (byte)0x67,
			(byte)0xe6, (byte)0x10, (byte)0x14, (byte)0xf6,
			(byte)0x67, (byte)0x6d, (byte)0x3c, (byte)0x67,
		};
	};

	@Override
	public void init(String password, int strength)
		throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, GeneralSecurityException
	{
		if (password.length() == 0)
			throw new IllegalArgumentException("password is empty");
		if (strength < 1 || (strength >= 32 && strength < 64))
			throw new IllegalArgumentException("PBKDF2 strength is out of range (must be between 1 and 31 for exponential strength or 64 and higher for iteration count)");

		byte[] combined_key = PBKDF.pbkdf2(pbkdf2HmacAlg(), password.getBytes("UTF-8"), salt(), strength < 64 ? (1<<strength) : strength, 64);
		//System.err.println(String.format("PBKDF2-%s[%d]: %s", pbkdf2HmacAlg(), strength, Util.bytesToHex(combined_key)));

		cipher = Cipher.getInstance(cipherAlg());
		cipherKey = new SecretKeySpec(Arrays.copyOfRange(combined_key, 0, 32), cipherFamily());
		mac = Mac.getInstance(hmacAlg());
		macKey = new SecretKeySpec(Arrays.copyOfRange(combined_key, 32, 64), hmacAlg());

		kdstrength = strength;
	}

	@Override
	public void init(byte[] key)
		throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, GeneralSecurityException
	{
		final int csize = cipherKeySize() / 8;
		final int hsize = hmacKeySize() / 8;
		if (key.length != csize + hsize)
			throw new InvalidKeySpecException("bad key size");
		this.cipher = Cipher.getInstance(cipherAlg());
		this.cipherKey = new SecretKeySpec(key, 0, csize, cipherFamily());
		this.mac = Mac.getInstance(hmacAlg());
		this.macKey = new SecretKeySpec(key, csize, hsize, hmacAlg());
		kdstrength = -1;
	}

	public void init(SecretKeySpec cipherKey, SecretKeySpec macKey)
		throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, GeneralSecurityException
	{
		this.cipher = Cipher.getInstance(cipherAlg());
		this.cipherKey = cipherKey;
		this.mac = Mac.getInstance(hmacAlg());
		this.macKey = macKey;
		kdstrength = -1;
	}

	@Override
	public int keySize()
	{
		return (cipherKeySize() + hmacKeySize()) / 8;
	}

	@Override
	public int strength() {
		return kdstrength;
	}

	@Override
	public boolean available() {
		try {
			cipher = Cipher.getInstance(cipherAlg());
		}
		catch (Exception e) {
			return false;
		}
		return true;
	}
}
