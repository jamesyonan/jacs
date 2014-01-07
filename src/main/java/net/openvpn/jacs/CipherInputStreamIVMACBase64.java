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

import javax.xml.bind.DatatypeConverter; // for base64
import java.nio.charset.Charset;
import java.io.InputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import javax.crypto.spec.SecretKeySpec;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.NoSuchPaddingException;
import java.security.GeneralSecurityException;

public class CipherInputStreamIVMACBase64 extends PipeInputBuffer {
	public static final int bufferSize = 4096;

	public static class Base64ParseError extends IOException {
		public Base64ParseError() {
			super("Base64 parse error");
		}
	}

	public static class KeyRequired extends IOException {
		public KeyRequired() {
			super("Key required");
		}
	}

	public static class IncorrectKeyType extends IOException {
		public IncorrectKeyType() {
			super("Incorrect key type");
		}
	}

	public static class Parms {
		private CipherMacSpec spec;
		private int strength;

		public void init(String password) throws IOException {
			try {
				spec.init(password, strength);
			}
			catch (NoSuchAlgorithmException e) {
				throw new IOExceptionWrapper(e);
			}
			catch (InvalidKeySpecException e) {
				throw new IOExceptionWrapper(e);
			}
			catch (NoSuchPaddingException e) {
				throw new IOExceptionWrapper(e);
			}
			catch (GeneralSecurityException e) {
				throw new IOExceptionWrapper(e);
			}
		}

		public void init(byte[] key) throws IOException {
			try {
				spec.init(key);
			}
			catch (NoSuchAlgorithmException e) {
				throw new IOExceptionWrapper(e);
			}
			catch (InvalidKeySpecException e) {
				throw new IOExceptionWrapper(e);
			}
			catch (NoSuchPaddingException e) {
				throw new IOExceptionWrapper(e);
			}
			catch (GeneralSecurityException e) {
				throw new IOExceptionWrapper(e);
			}
		}

		public void init(SecretKeySpec cipherKey, SecretKeySpec macKey) throws IOException {
			try {
				spec.init(cipherKey, macKey);
			}
			catch (NoSuchAlgorithmException e) {
				throw new IOExceptionWrapper(e);
			}
			catch (InvalidKeySpecException e) {
				throw new IOExceptionWrapper(e);
			}
			catch (NoSuchPaddingException e) {
				throw new IOExceptionWrapper(e);
			}
			catch (GeneralSecurityException e) {
				throw new IOExceptionWrapper(e);
			}
		}

		public boolean isKeyDerivedFromPassword() {
			return strength >= 1;
		}

	};

	private static class Base64Helper {
		Charset charset;

		public Base64Helper() {
			this.charset = Charset.forName("UTF-8");
		}

		Parms head(byte[] line) throws IOException {
			String s = new String(line, charset);
			if (s.startsWith(CipherOutputStreamIVMACBase64.head_tag)) {
				Parms p = new Parms();
				s = s.substring(CipherOutputStreamIVMACBase64.head_tag.length());
				String[] args = s.split("\\s+");
				for (String a : args) {
					if (a.length() > 0) {
						String[] kv = a.split(":", 2);
						if (kv.length == 2) {
							if (kv[0].equals("ALG")) {
								p.spec = JacsAlgs.getInstance(kv[1]);
								if (p.spec == null)
									throw new JacsAlgs.NotFound(kv[1]);
							} else if (kv[0].equals("STRENGTH")) {
								p.strength = Integer.parseInt(kv[1]);
							}
						}
					}
				}
				return p;
			} else
				return null;
		}

		byte[] parse(byte[] line) throws IOException {
			String s = new String(line, charset).trim();
			if (!s.matches("^[A-Za-z0-9/+=]*$"))
				throw new Base64ParseError();
			return DatatypeConverter.parseBase64Binary(s);
		}
	}

	private static class LineBuffer extends PipeInputBuffer {
		private InputStream is;

		public LineBuffer(InputStream is) {
			this.is = is;
		}

		@Override
		protected void getBytes(PipeOutputBuffer out) throws IOException {
			byte[] buf = new byte[bufferSize];
			int len = is.read(buf);
			if (len > 0)
				out.write(buf, 0, len);
		}

		public byte[] readLine() throws IOException {
			PipeOutputBuffer out = new PipeOutputBuffer();
			while (true) {
				int b = read();
				if (b < 0)
					break;
				out.write(b);
				if (b == '\n')
					break;
			}
			return out.getByteArray();
		}

		@Override
		public void close() throws IOException {
			is.close();
		}
	}

	private LineBuffer lbuf;
	private boolean passthruIfUnencrypted;
	private Base64Helper b64;
	private InputStream in;
	private String password;

	/**
	 * Decrypt a stream using the ciphertext format: Explicit IV,
	 * ciphertext data, and HMAC signature rendered as Base64.
	 *
	 * @param is Ciphertext will be read from this stream as Base64.
	 * @param password Decryption password, or null to obtain from
	 *        getKey() if needed.
	 * @param passthruIfUnencrypted If true, and input is not recognized
	 *        as a Jacs base64 ciphertext file, pipe the input through
	 *        verbatim.
	 */
	public CipherInputStreamIVMACBase64(InputStream is, String password, boolean passthruIfUnencrypted)
	{
		this.lbuf = new LineBuffer(is);
		this.passthruIfUnencrypted = passthruIfUnencrypted;
		this.b64 = new Base64Helper();
		this.password = password;
	}

	/**
	 * Derived classes should override this method to provide a
	 * key when needed.
	 *
	 * @return The password.
	 */
	public void getKey(Parms parms) throws IOException {
		throw new KeyRequired();
	}

	void getBytesCiphertext(PipeOutputBuffer out) throws IOException {
		while (out.size() < bufferSize) {
			byte[] line = lbuf.readLine();
			if (line.length == 0)
				break;
			byte[] ct = b64.parse(line);
			out.write(ct);
		}
	}

	@Override
	protected void getBytes(PipeOutputBuffer out) throws IOException {
		if (in == null) {
			byte[] line = lbuf.readLine();
			Parms parms = b64.head(line);
			if (parms != null) {
				if (password != null)
					parms.init(password);
				else
					getKey(parms);
				PipeInputBuffer ct = new PipeInputBuffer() {
						@Override
						protected void getBytes(PipeOutputBuffer out) throws IOException {
							getBytesCiphertext(out);
						}
					};
				try {
					in = new CipherInputStreamIVMAC(ct, parms.spec);
				}
				catch (InvalidKeyException e) {
					throw new IOExceptionWrapper(e);
				}
			} else {
				if (!passthruIfUnencrypted)
					throw new Base64ParseError();
				out.write(line);
				in = lbuf;
			}
		}
		byte[] buf = new byte[bufferSize];
		int len = in.read(buf);
		if (len > 0)
			out.write(buf, 0, len);
	}

	@Override
	public void close() throws IOException {
		if (in != null)
			in.close();
	}
}
