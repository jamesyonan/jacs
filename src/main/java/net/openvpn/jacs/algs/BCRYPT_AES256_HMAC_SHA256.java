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
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.security.MessageDigest;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.NoSuchPaddingException;
import java.security.GeneralSecurityException;
import java.io.UnsupportedEncodingException;

/**
 * Crypto parameters for BCRYPT + AES-256 + HMAC-SHA-256 signature.
 */
public class BCRYPT_AES256_HMAC_SHA256 extends CipherMacSpec {
	private int kdstrength = -1;

	@Override
	public String name() {
		return "BCRYPT-AES256-HMAC-SHA256";
	}

	@Override
	public CipherMacSpec create() {
		return new BCRYPT_AES256_HMAC_SHA256();
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
			(byte)0xe5, (byte)0x86, (byte)0xbe, (byte)0x0f,
			(byte)0x88, (byte)0xc8, (byte)0xe0, (byte)0x7e,
			(byte)0x5d, (byte)0x15, (byte)0xbd, (byte)0x4b,
			(byte)0xce, (byte)0x9e, (byte)0x88, (byte)0xd7
		};
	}

	@Override
	public void init(String password, int strength)
		throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException, GeneralSecurityException
	{
		if (password.length() == 0)
			throw new IllegalArgumentException("password is empty");
		if (strength < 4 || strength > 31)
			throw new IllegalArgumentException("BCrypt strength is out of range (must be between 4 and 31)");

		// Use BCrypt to derive a 24-byte key, then expand it to 64 bytes
		// using one round of SHA-512.  The resulting key will then be split
		// into two 32-byte keys to be used as cipher and HMAC keys.
		BCrypt bcrypt = new BCrypt();
		byte[] bcrypt_key = bcrypt.crypt_raw(password.getBytes("UTF-8"), salt(), strength);
		//System.err.println(String.format("BCrypt raw: %s", Util.bytesToHex(bcrypt_key)));
		MessageDigest digest = MessageDigest.getInstance("SHA-512");
		byte[] combined_key = digest.digest(bcrypt_key);
		//System.err.println(String.format("BCrypt[%d]: %s", strength, Util.bytesToHex(combined_key)));

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
