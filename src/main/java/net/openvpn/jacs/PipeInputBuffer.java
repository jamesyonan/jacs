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

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * Pipe class used internally.
 */
public abstract class PipeInputBuffer extends InputStream {
	private PipeOutputBuffer out;
	private ByteArrayInputStream in;

	public PipeInputBuffer() {
		out = new PipeOutputBuffer();
	}

	/**
	 * Called to refill pipe.
	 *
	 * @param out Method should write data here to refill the pipe.
	 */
	abstract protected void getBytes(PipeOutputBuffer out) throws IOException;

	private void more() throws IOException {
		if (in == null || in.available() == 0) {
			getBytes(out);
			in = out.getInputStream();
		}
	}

	@Override
	public int available() throws IOException {
		more();
		return in.available();
	}

	@Override
	public int read() throws IOException {
		more();
		return in.read();
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		more();
		return in.read(b, off, len);
	}

	@Override
	public boolean markSupported() {
		return false;
	}

	@Override
	public void mark(int readAheadLimit) {
	}

	@Override
	public void reset() {
	}
}
