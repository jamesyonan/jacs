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

import java.io.OutputStream;
import javax.crypto.CipherOutputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;

import java.io.IOException;
import java.security.InvalidKeyException;

import java.security.SecureRandom;

import java.security.InvalidAlgorithmParameterException;

/**
 * CipherOutputStream extension that supports Explicit IV and
 * HMAC integrity checking.  Constructor is initialized with
 * an OutputStream and a CipherMacSpec.
 *
 * Stream output format is as follows:
 * [ Explicit IV ] [ ciphertext ] [ HMAC signature ]
 */
public class CipherOutputStreamIVMAC extends CipherOutputStream {
	private static class OutputStreamMAC extends OutputStream {
		private OutputStream os;
		private Mac mac;
		private boolean closed;

		public OutputStreamMAC(OutputStream os, Mac mac, SecretKey macKey)
			throws InvalidKeyException
		{
			this.os = os;
			mac.init(macKey);
			this.mac = mac;
		}

		public OutputStream underlying_out() {
			return os;
		}

		@Override
		public void write(int b) throws IOException {
			mac.update((byte)b);
			os.write(b);
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			mac.update(b, off, len);
			os.write(b, off, len);
		}

		@Override
		public void flush() throws IOException {
			os.flush();
		}

		@Override
		public void close() throws IOException {
			if (!closed) {
				closed = true;
				byte[] sig = mac.doFinal();
				os.write(sig);
				os.close();
			}
		}
	}

	protected CipherMacSpec spec;
	protected boolean init;

	/**
	 * Encrypt a stream using the ciphertext format: Explicit IV,
	 * ciphertext data, and HMAC signature.
	 *
	 * @param os Ciphertext will be written to this stream.
	 * @param spec Parameters that define the encryption algorithm.
	 */
	public CipherOutputStreamIVMAC(OutputStream os, CipherMacSpec spec)
		throws InvalidKeyException
	{
		super(new OutputStreamMAC(os, spec.mac, spec.macKey), spec.cipher);
		this.spec = spec;
	}

	protected OutputStream underlying_out() {
		return ((OutputStreamMAC)out).underlying_out();
	}

	protected void pre_write() throws IOException {
		try {
			SecureRandom random = new SecureRandom();
			byte iv[] = new byte[spec.cipher.getBlockSize()];
			random.nextBytes(iv);
			//System.err.println(String.format("Generated IV: %s", Util.bytesToHex(iv)));
			spec.cipher.init(Cipher.ENCRYPT_MODE, spec.cipherKey, new IvParameterSpec(iv));
		} catch (InvalidKeyException e) {
			throw new IOExceptionWrapper(e);
		}
        catch (InvalidAlgorithmParameterException e) {
			throw new IOExceptionWrapper(e);
		}
		out.write(spec.cipher.getIV());
	}

	private void pre_write_check() throws IOException {
		if (!init) {
			pre_write();
			init = true;
		}
	}

	@Override
	public void write(int b) throws IOException {
		pre_write_check();
		super.write(b);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		pre_write_check();
		super.write(b, off, len);
	}

	@Override
	public void flush() throws IOException {
		pre_write_check();
		super.flush();
	}

	@Override
	public void close() throws IOException {
		pre_write_check();
		super.close();
	}
}
