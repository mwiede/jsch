/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2015-2018 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright 
     notice, this list of conditions and the following disclaimer in 
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package com.jcraft.jsch.jce;

import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.security.interfaces.*;
 
public class XDH implements com.jcraft.jsch.XDH {
  String name;
  byte[] Q_array;
  XECPublicKey publicKey;

  private KeyAgreement myKeyAgree;
  public void init(String name) throws Exception{
    this.name = name;
    myKeyAgree = KeyAgreement.getInstance("XDH");
    KeyPairGenXEC kpair = new KeyPairGenXEC();
    kpair.init(name);
    publicKey = kpair.getPublicKey();
    Q_array = rotate(publicKey.getU().toByteArray(), false);
    myKeyAgree.init(kpair.getPrivateKey());
  }

  public byte[] getQ() throws Exception{
    return Q_array;
  }

  public byte[] getSecret(byte[] Q) throws Exception{
    KeyFactory kf = KeyFactory.getInstance("XDH");
    BigInteger u = new BigInteger(rotate(Q, name.equals("X25519")));
    XECPublicKeySpec spec = new XECPublicKeySpec(publicKey.getParams(), u);
    PublicKey theirPublicKey = kf.generatePublic(spec);
    myKeyAgree.doPhase(theirPublicKey, true);
    return myKeyAgree.generateSecret();
  }

  // https://cr.yp.to/ecdh.html#validate
  public boolean validate(byte[] u) throws Exception{
    return true;
  }

  // RFC 7748,
  // 5. The X25519 and X448 Functions
  //   The u-coordinates are elements of the underlying field GF(2^255 - 19)
  //   or GF(2^448 - 2^224 - 1) and are encoded as an array of bytes, u, in
  //   little-endian order such that u[0] + 256*u[1] + 256^2*u[2] + ... +
  //   256^(n-1)*u[n-1] is congruent to the value modulo p and u[n-1] is
  //   minimal.  When receiving such an array, implementations of X25519
  //   (but not X448) MUST mask the most significant bit in the final byte.
  //   This is done to preserve compatibility with point formats that
  //   reserve the sign bit for use in other protocols and to increase
  //   resistance to implementation fingerprinting.
  // RFC 8731,
  // 3.1. Shared Secret Encoding
  //   When performing the X25519 or X448 operations, the integer values
  //   there will be encoded into byte strings by doing a fixed-length
  //   unsigned little-endian conversion, per [RFC7748].  It is only later
  //   when these byte strings are then passed to the ECDH function in SSH
  //   that the bytes are reinterpreted as a fixed-length unsigned big-
  //   endian integer value K, and then later that K value is encoded as a
  //   variable-length signed "mpint" before being fed to the hash algorithm
  //   used for key generation.  The mpint K is then fed along with other
  //   data to the key exchange method's hash function to generate
  //   encryption keys.
  private static byte[] rotate(byte[] in, boolean clearHigh){
    int len=in.length;
    byte[] out = new byte[len];

    for(int i=0; i<len; i++){
      out[i]=in[len-i-1];
    }

    if(clearHigh){
      out[0]&=(byte)0x7f;
    }

    return out;
  }
}
