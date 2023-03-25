/*
 * Copyright (c) 2015-2018 ymnk, JCraft,Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions
 * and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other materials provided with
 * the distribution.
 *
 * 3. The names of the authors may not be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL JCRAFT, INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.jcraft.jsch.jce;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.util.Arrays;
import javax.crypto.*;

public class XDH implements com.jcraft.jsch.XDH {
  byte[] Q_array;
  XECPublicKey publicKey;
  int keylen;

  private KeyAgreement myKeyAgree;

  @Override
  public void init(String name, int keylen) throws Exception {
    this.keylen = keylen;
    myKeyAgree = KeyAgreement.getInstance("XDH");
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
    NamedParameterSpec paramSpec = new NamedParameterSpec(name);
    kpg.initialize(paramSpec);
    KeyPair kp = kpg.genKeyPair();
    publicKey = (XECPublicKey) kp.getPublic();
    Q_array = rotate(publicKey.getU().toByteArray());
    myKeyAgree.init(kp.getPrivate());
  }

  @Override
  public byte[] getQ() throws Exception {
    return Q_array;
  }

  @Override
  public byte[] getSecret(byte[] Q) throws Exception {
    // The u coordinate in BigInteger format needs to be a positive value.
    // So zero extend the little-endian input before rotating into big-endian.
    // This should ensure that we end up with a positive BigInteger value.
    Q = rotate(Q);
    byte[] u = new byte[keylen + 1];
    System.arraycopy(Q, 0, u, 1, keylen);
    XECPublicKeySpec spec = new XECPublicKeySpec(publicKey.getParams(), new BigInteger(u));
    KeyFactory kf = KeyFactory.getInstance("XDH");
    PublicKey theirPublicKey = kf.generatePublic(spec);
    myKeyAgree.doPhase(theirPublicKey, true);
    return myKeyAgree.generateSecret();
  }

  // https://cr.yp.to/ecdh.html#validate
  // RFC 8731,
  // 3. Key Exchange Methods
  // Clients and servers MUST
  // also abort if the length of the received public keys are not the
  // expected lengths. An abort for these purposes is defined as a
  // disconnect (SSH_MSG_DISCONNECT) of the session and SHOULD use the
  // SSH_DISCONNECT_KEY_EXCHANGE_FAILED reason for the message
  // [IANA-REASON]. No further validation is required beyond what is
  // described in [RFC7748].
  @Override
  public boolean validate(byte[] u) throws Exception {
    return u.length == keylen;
  }

  // RFC 7748,
  // 5. The X25519 and X448 Functions
  // The u-coordinates are elements of the underlying field GF(2^255 - 19)
  // or GF(2^448 - 2^224 - 1) and are encoded as an array of bytes, u, in
  // little-endian order such that u[0] + 256*u[1] + 256^2*u[2] + ... +
  // 256^(n-1)*u[n-1] is congruent to the value modulo p and u[n-1] is
  // minimal. When receiving such an array, implementations of X25519
  // (but not X448) MUST mask the most significant bit in the final byte.
  // This is done to preserve compatibility with point formats that
  // reserve the sign bit for use in other protocols and to increase
  // resistance to implementation fingerprinting.
  private byte[] rotate(byte[] in) {
    int len = in.length;
    byte[] out = new byte[len];

    for (int i = 0; i < len; i++) {
      out[i] = in[len - i - 1];
    }

    return Arrays.copyOf(out, keylen);
  }
}
