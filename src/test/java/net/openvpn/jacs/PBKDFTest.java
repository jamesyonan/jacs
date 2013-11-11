// Copyright (C) 2011 - Will Glozer.  All rights reserved.
// This code is released under the Apache License,
// Version 2.0, January 2004
// http://www.apache.org/licenses/

package net.openvpn.jacs;

import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

public class PBKDFTest {
    @Test
    public void pbkdf2_hmac_sha1_rfc6070() throws Exception {
        String alg = "HmacSHA1";
        byte[] P, S;
        int c, dkLen;
        String DK;

        P = "password".getBytes("UTF-8");
        S = "salt".getBytes("UTF-8");
        c = 1;
        dkLen = 20;
        DK = "0c60c80f961f0e71f3a9b524af6012062fe037a6";

        assertArrayEquals(CryptoTestUtil.decode(DK), PBKDF.pbkdf2(alg, P, S, c, dkLen));

        P = "password".getBytes("UTF-8");
        S = "salt".getBytes("UTF-8");
        c = 2;
        dkLen = 20;
        DK = "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957";

        assertArrayEquals(CryptoTestUtil.decode(DK), PBKDF.pbkdf2(alg, P, S, c, dkLen));

        P = "password".getBytes("UTF-8");
        S = "salt".getBytes("UTF-8");
        c = 4096;
        dkLen = 20;
        DK = "4b007901b765489abead49d926f721d065a429c1";

        assertArrayEquals(CryptoTestUtil.decode(DK), PBKDF.pbkdf2(alg, P, S, c, dkLen));

        P = "password".getBytes("UTF-8");
        S = "salt".getBytes("UTF-8");
        c = 16777216;
        dkLen = 20;
        DK = "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984";

        assertArrayEquals(CryptoTestUtil.decode(DK), PBKDF.pbkdf2(alg, P, S, c, dkLen));

        P = "passwordPASSWORDpassword".getBytes("UTF-8");
        S = "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes("UTF-8");
        c = 4096;
        dkLen = 25;
        DK = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038";

        assertArrayEquals(CryptoTestUtil.decode(DK), PBKDF.pbkdf2(alg, P, S, c, dkLen));

        P = "pass\0word".getBytes("UTF-8");
        S = "sa\0lt".getBytes("UTF-8");
        c = 4096;
        dkLen = 16;
        DK = "56fa6aa75548099dcc37d7f03425e0c3";

        assertArrayEquals(CryptoTestUtil.decode(DK), PBKDF.pbkdf2(alg, P, S, c, dkLen));
    }

    @Test
    public void pbkdf2_hmac_sha1_rfc3962() throws Exception {
        String alg = "HmacSHA1";
        byte[] P, S;
        int c, dkLen;
        String DK;

        P = "password".getBytes("UTF-8");
        S = "ATHENA.MIT.EDUraeburn".getBytes("UTF-8");
        c = 1;

        dkLen = 16;
        DK = "cdedb5281bb2f801565a1122b2563515";
        assertArrayEquals(CryptoTestUtil.decode(DK), PBKDF.pbkdf2(alg, P, S, c, dkLen));

        dkLen = 32;
        DK = "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837";
        assertArrayEquals(CryptoTestUtil.decode(DK), PBKDF.pbkdf2(alg, P, S, c, dkLen));

        P = "password".getBytes("UTF-8");
        S = "ATHENA.MIT.EDUraeburn".getBytes("UTF-8");
        c = 2;

        dkLen = 16;
        DK = "01dbee7f4a9e243e988b62c73cda935d";
        assertArrayEquals(CryptoTestUtil.decode(DK), PBKDF.pbkdf2(alg, P, S, c, dkLen));

        dkLen = 32;
        DK = "01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86";
        assertArrayEquals(CryptoTestUtil.decode(DK), PBKDF.pbkdf2(alg, P, S, c, dkLen));

        P = "password".getBytes("UTF-8");
        S = "ATHENA.MIT.EDUraeburn".getBytes("UTF-8");
        c = 1200;

        dkLen = 16;
        DK = "5c08eb61fdf71e4e4ec3cf6ba1f5512b";
        assertArrayEquals(CryptoTestUtil.decode(DK), PBKDF.pbkdf2(alg, P, S, c, dkLen));

        dkLen = 32;
        DK = "5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13";
        assertArrayEquals(CryptoTestUtil.decode(DK), PBKDF.pbkdf2(alg, P, S, c, dkLen));

        P = "password".getBytes("UTF-8");
        S = new BigInteger("1234567878563412", 16).toByteArray();
        c = 5;

        dkLen = 16;
        DK = "d1daa78615f287e6a1c8b120d7062a49";
        assertArrayEquals(CryptoTestUtil.decode(DK), PBKDF.pbkdf2(alg, P, S, c, dkLen));

        dkLen = 32;
        DK = "d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee";
        assertArrayEquals(CryptoTestUtil.decode(DK), PBKDF.pbkdf2(alg, P, S, c, dkLen));
    }

    @Test
    public void pbkdf2_hmac_sha256_scrypt() throws Exception {
        String alg = "HmacSHA256";
        byte[] P, S;
        int c, dkLen;
        String DK;

        P = "password".getBytes("UTF-8");
        S = "salt".getBytes("UTF-8");
        c = 4096;
        dkLen = 32;
        DK = "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a";

        assertArrayEquals(CryptoTestUtil.decode(DK), PBKDF.pbkdf2(alg, P, S, c, dkLen));
    }
}
