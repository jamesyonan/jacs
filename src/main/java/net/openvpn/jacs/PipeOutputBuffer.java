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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * An output buffer derived from ByteArrayOutputStream,
 * with methods provided for reading the data written
 * thus far.
 */
public class PipeOutputBuffer extends ByteArrayOutputStream {
	/**
	 * Get the data written so far to the ByteArrayOutputStream
	 * as a byte array.
	 *
	 * @return Byte array of data written so far.
	 */
	public byte[] getByteArray() {
		byte[] ret = Arrays.copyOf(buf, count);
		reset();
		return ret;
	}

	/**
	 * Get the data written so far to the ByteArrayOutputStream
	 * as a ByteArrayInputStream.
	 *
	 * @return ByteArrayInputStream of data written so far.
	 */
	public ByteArrayInputStream getInputStream() {
		return new ByteArrayInputStream(getByteArray());
	}
}
