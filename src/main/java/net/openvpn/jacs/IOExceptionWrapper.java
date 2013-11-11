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

import java.io.IOException;

/**
 * Wrap an Exception in a IOException.  This is used by
 * CipherInputStreamIVMAC and CipherOutputStreamIVMAC to
 * pass exceptions back to their clients.
 */
public class IOExceptionWrapper extends IOException {
	public Exception wrapExc;

	public IOExceptionWrapper(Exception e) {
		super(e.toString());
		wrapExc = e;
	}
}
