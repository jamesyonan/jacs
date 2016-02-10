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

package net.openvpn.jacs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Test;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.lang.StringBuilder;

import java.security.SecureRandom;

public class JacsTest {
	private static final String enc_1984 = // encrypted with password "mygoodness"
		"===== BEGIN JACS ENCRYPTED FILE ALG:PBKDF2-SHA1-AES256-HMAC-SHA256 STRENGTH:12\n" +
		"YYLIeTC0Q/5q+tYMIN7dPgQYh2YjEFvFRl1+PEFYjLaOlbQUFPDBq1/13lyUyJTC\n" +
		"yujbs/2fBiPsBHlob7ApKwWfhV/hOYp3T5BJjLao8q0713aDHv9JmD7Na56/0P/Q\n" +
		"oQjuWR0HJDCX6bWVjepjJEB1DlYdyfdkJAvVP5YJtz+wUURqk14ZPn6EDaIvsHkv\n" +
		"+dAgYE8SKFzthM3X27Jw29UahHfq52DqKm62w/51VPR81A19uREHiAc+UoGX3wxd\n" +
		"a2HFQ5ZbDf/yoAYKUcSEZomMArOcTvk23vKAGcRZrQbKJQTjRO766/UxKEt6+P6p\n" +
		"xcPBGvL/mOvHrDZt9OC7CHm4+2jSpeWTvU0dj4f4ygwjnLq4xbPnolMGC/THtai3\n" +
		"iN7tGjIvS4UNvfS5z07VRPhxVKNMruinXDOaPdqWWX9ew2XugEqKEm8MPQKvTUwa\n" +
		"H4MYXpo8yFuOi7uEo+j5M+Q5UqwHR+kS2P/cci5LNoM=\n";

	private static final String plain_1984 =
		"It was a bright cold day in April, and the clocks\n" +
		"were striking thirteen. Winston Smith, his chin nuzzled\n" +
		"into his breast in an effort to escape the vile wind,\n" +
		"slipped quickly through the glass doors of Victory\n" +
		"Mansions, though not quickly enough to prevent a\n" +
		"swirl of gritty dust from entering along with him.\n";

	@Test
	public void testDecrypt1984() throws Exception {
		ByteArrayInputStream in = new ByteArrayInputStream(enc_1984.getBytes("UTF-8"));
		CipherInputStreamIVMACBase64 cis = new CipherInputStreamIVMACBase64(in, "mygoodness", false);
		ByteArrayOutputStream outplain = new ByteArrayOutputStream();
		xfer(cis, outplain);
		String new_1984 = outplain.toString("UTF-8");
		assertEquals(new_1984, plain_1984);
	}

	@Test(expected = CipherInputStreamIVMAC.HMACVerificationFailed.class)
	public void testDecrypt1984BadPassword() throws Exception {
		ByteArrayInputStream in = new ByteArrayInputStream(enc_1984.getBytes("UTF-8"));
		CipherInputStreamIVMACBase64 cis = new CipherInputStreamIVMACBase64(in, "mybadness", false);
		ByteArrayOutputStream outplain = new ByteArrayOutputStream();
		xfer(cis, outplain);
	}

	@Test
	public void testEncryptDecrypt1984UsingPassword() throws Exception {
		testEncryptDecryptStringUsingPassword(plain_1984);
	}

	@Test
	public void testEncryptDecryptLargeStringUsingPassword() throws Exception {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 1000; i += 1) {
			sb.append(plain_1984);
		}
		testEncryptDecryptStringUsingPassword(sb.toString());
	}

	@Test
	public void testEncryptDecrypt1984UsingKey() throws Exception {
		testEncryptDecryptStringUsingKey(plain_1984);
	}

	@Test
	public void testEncryptDecryptLargeStringUsingKey() throws Exception {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 1000; i += 1) {
			sb.append(plain_1984);
		}
		testEncryptDecryptStringUsingKey(sb.toString());
	}

	private void testEncryptDecryptStringUsingPassword(String content) throws Exception {
		final String password = "foobar";
		for (String alg : JacsAlgs.enumAlgs()) {
			ByteArrayInputStream inplain = new ByteArrayInputStream(content.getBytes("UTF-8"));
			CipherMacSpec spec = JacsAlgs.getInstance(alg);
			spec.init(password, 16);
			PipeOutputBuffer outenc = new PipeOutputBuffer();
			CipherOutputStreamIVMACBase64 cos = new CipherOutputStreamIVMACBase64(outenc, spec);
			xfer(inplain, cos);

			ByteArrayInputStream isenc = outenc.getInputStream();
			CipherInputStreamIVMACBase64 cis = new CipherInputStreamIVMACBase64(isenc, null, false) {
					@Override
					public void getKey(CipherInputStreamIVMACBase64.Parms parms) throws IOException {
						assertEquals(parms.isKeyDerivedFromPassword(), true);
						parms.init(password);
					}
				};
			ByteArrayOutputStream outplain = new ByteArrayOutputStream();
			xfer(cis, outplain);
			String new_1984 = outplain.toString("UTF-8");
			assertEquals(new_1984, content);
		}
	}

	private void testEncryptDecryptStringUsingKey(String content) throws Exception {
		SecureRandom random = new SecureRandom();
		for (String alg : JacsAlgs.enumAlgs()) {
			ByteArrayInputStream inplain = new ByteArrayInputStream(content.getBytes("UTF-8"));
			CipherMacSpec spec = JacsAlgs.getInstance(alg);
			final byte key[] = new byte[spec.keySize()];
			random.nextBytes(key);

			spec.init(key);
			PipeOutputBuffer outenc = new PipeOutputBuffer();
			CipherOutputStreamIVMACBase64 cos = new CipherOutputStreamIVMACBase64(outenc, spec);
			xfer(inplain, cos);

			ByteArrayInputStream isenc = outenc.getInputStream();
			CipherInputStreamIVMACBase64 cis = new CipherInputStreamIVMACBase64(isenc, null, false) {
					@Override
					public void getKey(CipherInputStreamIVMACBase64.Parms parms) throws IOException {
						assertEquals(parms.isKeyDerivedFromPassword(), false);
						parms.init(key);
					}
				};
			ByteArrayOutputStream outplain = new ByteArrayOutputStream();
			xfer(cis, outplain);
			String new_1984 = outplain.toString("UTF-8");
			assertEquals(new_1984, content);
		}
	}

	private static void xfer(InputStream is, OutputStream os) throws IOException {
		try {
			byte[] buf = new byte[4096];
			while (true) {
				int len = is.read(buf);
				if (len < 0)
					break;
				if (len > 0)
					os.write(buf, 0, len);
			}
		}
		finally {
			is.close();
			os.close();
		}
	}
}
