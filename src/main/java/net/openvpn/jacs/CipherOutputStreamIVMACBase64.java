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
import javax.xml.bind.DatatypeConverter; // for base64
import java.nio.charset.Charset;
import java.io.OutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;

public class CipherOutputStreamIVMACBase64 extends CipherOutputStreamIVMAC {
	public static final String head_tag = "===== BEGIN JACS ENCRYPTED FILE";

	private static class OutputStreamBase64 extends OutputStream {
		private OutputStream os;
		private Charset charset;
		private byte[] lbuf;
		private int lbcount;
		private boolean closed;

		public OutputStreamBase64(OutputStream os)
		{
			this.os = os;
			this.charset = Charset.forName("UTF-8");
			this.lbuf = new byte[48];
		}

		public void write_string(String string) throws IOException {
			os.write(string.getBytes(charset));
		}

		private void lbuf_flush() throws IOException {
			if (lbcount > 0) {
				write_string(DatatypeConverter.printBase64Binary(Arrays.copyOf(lbuf, lbcount))+'\n');
				lbcount = 0;
			}
		}

		@Override
		public void write(int b) throws IOException {
			if (lbcount == lbuf.length)
				lbuf_flush();
			lbuf[lbcount] = (byte)b;
			lbcount += 1;
		}

		@Override
		public void write(byte[] b) throws IOException {
			write(b, 0, b.length);
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			while (len > 0) {
				if (lbcount == lbuf.length)
					lbuf_flush();
				int remaining = lbuf.length - lbcount;
				if (remaining > len)
					remaining = len;
				System.arraycopy(b, off, lbuf, lbcount, remaining);
				len -= remaining;
				lbcount += remaining;
				off += remaining;
			}
		}

		@Override
		public void flush() throws IOException {
		}

		@Override
		public void close() throws IOException {
			if (!closed) {
				closed = true;
				lbuf_flush();
				os.close();
			}
		}
	}

	/**
	 * Encrypt a stream using the ciphertext format: Explicit IV,
	 * ciphertext data, and HMAC signature rendered as Base64.
	 *
	 * @param os Ciphertext will be written to this stream as Base64.
	 * @param spec Parameters that define the encryption algorithm.
	 */
	public CipherOutputStreamIVMACBase64(OutputStream os, CipherMacSpec spec)
		throws InvalidKeyException
	{
		super(new OutputStreamBase64(os), spec);
	}

	protected void pre_write() throws IOException {
		write_string(String.format("%s ALG:%s STRENGTH:%d\n",
					head_tag, spec.name(), spec.strength()));
		super.pre_write();
	}

	private void write_string(String string) throws IOException {
		OutputStreamBase64 osb64 = (OutputStreamBase64)underlying_out();
		osb64.write_string(string);
	}
}
