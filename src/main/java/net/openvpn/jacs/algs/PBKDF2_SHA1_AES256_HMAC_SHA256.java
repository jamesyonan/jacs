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
public class PBKDF2_SHA1_AES256_HMAC_SHA256 extends CipherMacSpec {
	private int kdstrength = -1;

	@Override
	public String name() {
		return "PBKDF2-SHA1-AES256-HMAC-SHA256";
	}

	@Override
	public CipherMacSpec create() {
		return new PBKDF2_SHA1_AES256_HMAC_SHA256();
	}

	protected String pbkdf2HmacAlg() {
		return "HmacSHA1";
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

	protected byte[] cipherSalt() {
		return new byte[] {
			(byte)0xe9, (byte)0x66, (byte)0x97, (byte)0xb7,
			(byte)0xa6, (byte)0xdb, (byte)0x7f, (byte)0x4a,
			(byte)0x45, (byte)0x57, (byte)0x76, (byte)0xa0,
			(byte)0x91, (byte)0x86, (byte)0x32, (byte)0x6e,
		};
	}

	protected String hmacAlg() {
		return "HmacSHA256";
	}

	protected int hmacKeySize() {
		return 256;
	}

	protected byte[] hmacSalt() {
		return new byte[] {
			(byte)0xd6, (byte)0x83, (byte)0x8f, (byte)0x7a,
			(byte)0x80, (byte)0x5c, (byte)0x33, (byte)0x8a,
			(byte)0x8d, (byte)0xc6, (byte)0x19, (byte)0x2d,
			(byte)0x0b, (byte)0x0b, (byte)0x45, (byte)0x3e,
		};
	}

	private static SecretKeySpec secretKeyPBKDF2(
				String pbkdf2HmacAlg,
				String alg,
				String password,
				byte[] salt,
				int strength,
				int keySize)
		throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, GeneralSecurityException
	{
		if (password.length() == 0)
			throw new IllegalArgumentException("password is empty");
		if (strength < 1 || (strength >= 32 && strength < 64))
			throw new IllegalArgumentException("PBKDF2 strength is out of range (must be between 1 and 31 for exponential strength or 64 and higher for iteration count)");

		byte[] raw_key = PBKDF.pbkdf2(pbkdf2HmacAlg, password.getBytes("UTF-8"), salt, strength < 64 ? (1<<strength) : strength, keySize/8);
		//System.err.println(String.format("PBKDF2-%s[%d]: %s", pbkdf2HmacAlg, strength, Util.bytesToHex(raw_key)));
		SecretKeySpec skey = new SecretKeySpec(raw_key, alg);
		return skey;
	}

	@Override
	public void init(String password, int strength)
		throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, GeneralSecurityException
	{
		cipher = Cipher.getInstance(cipherAlg());
		cipherKey = secretKeyPBKDF2(
				pbkdf2HmacAlg(),
				cipherFamily(),
				password,
				cipherSalt(),
				strength,
				cipherKeySize());
		mac = Mac.getInstance(hmacAlg());
		macKey = secretKeyPBKDF2(
				pbkdf2HmacAlg(),
				hmacAlg(),
				password,
				hmacSalt(),
				strength,
				hmacKeySize());
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

	@Override
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
