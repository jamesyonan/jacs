// Copyright (C) 2011 - Will Glozer.  All rights reserved.
// This code is released under the Apache License,
// Version 2.0, January 2004
// http://www.apache.org/licenses/

package net.openvpn.jacs;

public class CryptoTestUtil {
    public static byte[] decode(String str) {
        byte[] bytes = new byte[str.length() / 2];
        int index = 0;

        for (int i = 0; i < str.length(); i += 2) {
            int high = hexValue(str.charAt(i));
            int low = hexValue(str.charAt(i + 1));
            bytes[index++] = (byte) ((high << 4) + low);
        }

        return bytes;
    }

    public static int hexValue(char c) {
        return c >= 'a' ? c - 87 : c - 48;
    }
}
