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

import java.util.Arrays;

import java.io.InputStream;
import javax.crypto.CipherInputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;

/**
 * CipherInputStream extension that supports Explicit IV and
 * HMAC integrity checking.  Constructor is initialized with
 * an InputStream and a CipherMacSpec.
 *
 * Expected stream format is as follows:
 * [ Explicit IV ] [ ciphertext ] [ HMAC signature ]
 */
public class CipherInputStreamIVMAC extends CipherInputStream {
	public static final int bufferSize = 4096;

	/**
	 * This exception is thrown in the close() method
	 * on HMAC integrity check failure.
	 * NOTE: client must call close() method in order
	 * for this check to be performed.
	 */
	public static class HMACVerificationFailed extends IOException {
		public HMACVerificationFailed() {
			super("HMAC verification failed");
		}
	}

	/**
	 * This exception is thrown if the IV cannot be read
	 * from the stream.
	 */
	public static class CannotReadIVBytes extends IOException {
		public CannotReadIVBytes() {
			super("Cannot read IV bytes");
		}
	}

	private static class InputStreamMAC extends InputStream {
		private InputStream is;
		private Mac mac;
		private boolean closed;

		private int maclen;

		private byte[] buf;
		private int bufoffset;
		private int buflen;
		private boolean eof;

		public InputStreamMAC(InputStream is, Mac mac, SecretKey macKey)
			throws InvalidKeyException
		{
			this.is = is;
			mac.init(macKey);
			this.maclen = mac.getMacLength();
			this.mac = mac;
			this.buf = new byte[bufferSize+this.maclen];
		}

		private void reset_buf() {
			int remaining = buflen - bufoffset;
			if (bufoffset > 0 && remaining > 0)
				System.arraycopy(buf, bufoffset, buf, 0, remaining);
			bufoffset = 0;
			buflen = remaining;
		}

		private void read_buf() throws IOException {
			if (!eof) {
				while (buflen < buf.length) {
					int remaining = buf.length - buflen;
					int n = is.read(buf, buflen, remaining);
					if (n < 0) {
						eof = true;
						break;
					}
					buflen += n;
				}
			}
		}

		private int read_next() throws IOException {
			int avail = available();
			if (avail == 0) {
				reset_buf();
				read_buf();
				avail = available();
			}
			return avail;
		}

		@Override
		public int available() throws IOException {
			int avail = buflen - bufoffset - this.maclen;
			if (avail < 0)
				avail = 0;
			return avail;
		}

		@Override
		public int read() throws IOException {
			int ret = -1;
			int avail = read_next();
			if (avail > 0) {
				ret = buf[bufoffset];
				bufoffset += 1;
				mac.update((byte)ret);
			}
			return ret;
		}

		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			int avail = read_next();
			int actual = avail;
			if (actual > 0) {
				if (actual > len)
					actual = len;
				System.arraycopy(buf, bufoffset, b, off, actual);
				mac.update(buf, bufoffset, actual);
				bufoffset += actual;
			}
			if (eof && avail == 0)
				actual = -1;
			return actual;
		}

		@Override
		public void close() throws IOException {
			if (!closed) {
				closed = true;
				boolean good = false;
				byte[] sig = mac.doFinal();
				read_next();
				int avail = buflen - bufoffset;
				if (eof && avail == sig.length) {
					byte[] saved_sig = Arrays.copyOfRange(buf, bufoffset, buflen);
					if (Arrays.equals(sig, saved_sig))
						good = true;
				}
				is.close();
				if (!good)
					throw new HMACVerificationFailed();
			}
		}
	}

	private Cipher cipher;
	private SecretKey cipherKey;
	private boolean init;

	/**
	 * Decrypt a stream using the ciphertext format: Explicit IV,
	 * ciphertext data, and HMAC signature.
	 *
	 * @param is Ciphertext will be read from this stream.
	 * @param spec Parameters that define the decryption algorithm.
	 */
	public CipherInputStreamIVMAC(InputStream is, CipherMacSpec spec)
		throws InvalidKeyException
	{
		super(new InputStreamMAC(is, spec.mac, spec.macKey), spec.cipher);
		this.cipher = spec.cipher;
		this.cipherKey = spec.cipherKey;
	}

	private void read_iv_on_init() throws IOException {
		if (!init) {
			int bs = cipher.getBlockSize();
			byte[] iv = new byte[bs];
			int off = 0;
			while (off < bs) {
				int remaining = bs - off;
				int n = in.read(iv, off, remaining);
				if (n < 0 || n > remaining)
					throw new CannotReadIVBytes();
				off += n;
			}
			try {
				cipher.init(Cipher.DECRYPT_MODE, cipherKey, new IvParameterSpec(iv));
			} catch (InvalidKeyException e) {
				throw new IOExceptionWrapper(e);
			} catch (InvalidAlgorithmParameterException e) {
				throw new IOExceptionWrapper(e);
			}
			init = true;
		}
	}

	@Override
	public int read() throws IOException {
		read_iv_on_init();
		return super.read();
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		read_iv_on_init();
		return super.read(b, off, len);
	}

	@Override
	public int available() throws IOException {
		if (init)
			return super.available();
		else
			return 0;
	}
}
