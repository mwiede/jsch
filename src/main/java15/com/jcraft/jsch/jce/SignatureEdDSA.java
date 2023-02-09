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
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import com.jcraft.jsch.Buffer;

abstract class SignatureEdDSA implements com.jcraft.jsch.SignatureEdDSA {

  Signature signature;
  KeyFactory keyFactory;

  abstract String getName();

  abstract String getAlgo();

  abstract int getKeylen();

  @Override
  public void init() throws Exception {
    signature = java.security.Signature.getInstance("EdDSA");
    keyFactory = KeyFactory.getInstance("EdDSA");
  }

  // RFC 8032,
  // 5.1. Ed25519ph, Ed25519ctx, and Ed25519
  // ...
  // 5.1.3. Decoding
  // Decoding a point, given as a 32-octet string, is a little more
  // complicated.
  //
  // 1. First, interpret the string as an integer in little-endian
  // representation. Bit 255 of this number is the least significant
  // bit of the x-coordinate and denote this value x_0. The
  // y-coordinate is recovered simply by clearing this bit. If the
  // resulting value is >= p, decoding fails.
  //
  // 5.2. Ed448ph and Ed448
  // ...
  // 5.2.3. Decoding
  // Decoding a point, given as a 57-octet string, is a little more
  // complicated.
  //
  // 1. First, interpret the string as an integer in little-endian
  // representation. Bit 455 of this number is the least significant
  // bit of the x-coordinate and denote this value x_0. The
  // y-coordinate is recovered simply by clearing this bit. If the
  // resulting value is >= p, decoding fails.
  @Override
  public void setPubKey(byte[] y_arr) throws Exception {
    y_arr = rotate(y_arr);
    boolean xOdd = (y_arr[0] & 0x80) != 0;
    y_arr[0] &= 0x7f;
    BigInteger y = new BigInteger(y_arr);

    NamedParameterSpec paramSpec = new NamedParameterSpec(getAlgo());
    EdECPublicKeySpec pubSpec = new EdECPublicKeySpec(paramSpec, new EdECPoint(xOdd, y));
    PublicKey pubKey = keyFactory.generatePublic(pubSpec);
    signature.initVerify(pubKey);
  }

  @Override
  public void setPrvKey(byte[] bytes) throws Exception {
    NamedParameterSpec paramSpec = new NamedParameterSpec(getAlgo());
    EdECPrivateKeySpec privSpec = new EdECPrivateKeySpec(paramSpec, bytes);
    PrivateKey prvKey = keyFactory.generatePrivate(privSpec);
    signature.initSign(prvKey);
  }

  @Override
  public byte[] sign() throws Exception {
    byte[] sig = signature.sign();
    return sig;
  }

  @Override
  public void update(byte[] foo) throws Exception {
    signature.update(foo);
  }

  @Override
  public boolean verify(byte[] sig) throws Exception {
    int i = 0;
    int j = 0;
    byte[] tmp;
    Buffer buf = new Buffer(sig);

    String foo = new String(buf.getString(), StandardCharsets.UTF_8);
    if (foo.equals(getName())) {
      j = buf.getInt();
      i = buf.getOffSet();
      tmp = new byte[j];
      System.arraycopy(sig, i, tmp, 0, j);
      sig = tmp;
    }

    return signature.verify(sig);
  }

  private byte[] rotate(byte[] in) {
    int len = in.length;
    byte[] out = new byte[len];

    for (int i = 0; i < len; i++) {
      out[i] = in[len - i - 1];
    }

    return Arrays.copyOf(out, getKeylen());
  }
}
