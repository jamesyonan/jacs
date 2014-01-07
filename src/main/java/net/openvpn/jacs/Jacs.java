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

//import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Console;
import java.security.Provider;
import java.security.Security;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileNotFoundException;

public class Jacs {
	public static void main(String[] args)
		throws Exception
	{
		//Security.addProvider(new BouncyCastleProvider());

		if (args.length == 1 && args[0].equals("algs")) {
			for (String alg : JacsAlgs.enumAlgs())
				System.out.println(alg);
			System.exit(0);
		}

		if (args.length == 6 && (args[0].equals("E") || args[0].equals("E64"))) {
			InputStream fin = openInput(args[4]);
			OutputStream fout = openOutput(args[5]);

			CipherMacSpec spec = getInstance(args[1], args[2], args[3], true);
			OutputStream cos = args[0].equals("E64") ?
				new CipherOutputStreamIVMACBase64(fout, spec)
				: new CipherOutputStreamIVMAC(fout, spec);

			xfer(fin, cos);
			cos.close();
			fin.close();
		} else if (args.length == 6 && args[0].equals("D")) {
			InputStream fin = openInput(args[4]);
			OutputStream fout = openOutput(args[5]);

			CipherMacSpec spec = getInstance(args[1], args[2], args[3], false);
			InputStream cin = new CipherInputStreamIVMAC(fin, spec);

			xfer(cin, fout);
			cin.close();
			fout.close();
		} else if (args.length == 4 && (args[0].equals("D64") || args[0].equals("D64A"))) {
			InputStream fin = openInput(args[2]);
			OutputStream fout = openOutput(args[3]);

			String pw = args[1];
			if (pw.equals("."))
				pw = null;
			InputStream cin = new CipherInputStreamIVMACBase64(fin, pw, args[0].equals("D64A")) {
					@Override
					public void getKey(CipherInputStreamIVMACBase64.Parms parms) throws IOException {
						if (!parms.isKeyDerivedFromPassword())
							throw new CipherInputStreamIVMACBase64.IncorrectKeyType();
						String pw = getPw(false);
						parms.init(pw);
					}
				};

			xfer(cin, fout);
			cin.close();
			fout.close();
		} else {
			usage();
		}
	}

	public static String getPw(boolean confirm) {
		Console console = System.console();
		char[] pw = console.readPassword("Password:");
		String ret = new String(pw);
		if (confirm) {
			pw = console.readPassword("Confirm Password:");
			if (!ret.equals(new String(pw))) {
				System.err.println("passwords do not match");
				System.exit(1);
			}
		}
		return ret;
	}

	public static CipherMacSpec getInstance(String name, String password, String strength, boolean confirmPassword)
		throws Exception
	{
		CipherMacSpec ret = JacsAlgs.getInstance(name);
		if (ret == null) {
			System.err.println("unknown algorithm: " + name);
			System.exit(2);
		}
		if (password.equals("."))
			password = getPw(confirmPassword);
		ret.init(password, Integer.parseInt(strength));
		return ret;
	}

	public static InputStream openInput(String path) throws FileNotFoundException {
		if (path.equals("stdin"))
			return System.in;
		else
			return new FileInputStream(new File(path)); 
	}

	public static OutputStream openOutput(String path) throws FileNotFoundException {
		if (path.equals("stdout"))
			return System.out;
		else
			return new FileOutputStream(new File(path)); 
	}

	public static void xfer(InputStream is, OutputStream os) throws IOException {
		byte[] buf = new byte[4096];
		while (true) {
			int len = is.read(buf);
			if (len < 0)
				break;
			if (len > 0)
				os.write(buf, 0, len);
		}
	}

	public static void usage() {
		System.err.println("jacs 0.5.2: symmetric encryption tool");
		System.err.println("usage:");
		System.err.println("  encrypt : jacs E <alg> <password> <strength> <infile> <outfile>");
		System.err.println("  decrypt : jacs D <alg> <password> <strength> <infile> <outfile>");
		System.err.println("  encrypt to base64   : jacs E64 <alg> <password> <strength> <infile> <outfile>");
		System.err.println("  decrypt from base64 : jacs D64[A] <password> <infile> <outfile>");
		System.err.println("algs: ");
		for (String alg : JacsAlgs.enumAlgs())
			System.err.println("  "+alg);
		System.err.println("password   : password or '.' to prompt from stdin without echo");
		System.err.println("strength   : strength of password derivation (1 to 32 for exponential");
		System.err.println("             strength or 64 and higher for iteration count)");
		System.err.println("infile     : input pathname or 'stdin'");
		System.err.println("outfile    : output pathname or 'stdout'");
		System.err.println("'A' suffix : for D64, pass through input if not encrypted");
		System.exit(2);
	}
}
