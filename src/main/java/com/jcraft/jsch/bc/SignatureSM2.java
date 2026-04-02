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

package com.jcraft.jsch.bc;

import com.jcraft.jsch.Buffer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;

public class SignatureSM2 implements com.jcraft.jsch.SignatureSM2 {

  private static final String KEY_TYPE = "sm2";
  private static final byte[] DEFAULT_ID = "1234567812345678".getBytes(StandardCharsets.UTF_8);

  private static final ECDomainParameters DOMAIN_PARAMS;

  static {
    X9ECParameters x9 = GMNamedCurves.getByName("sm2p256v1");
    DOMAIN_PARAMS =
        new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
  }

  private SM2Signer signer;

  @Override
  public void init() throws Exception {
    signer = new SM2Signer();
  }

  @Override
  public void setPubKey(byte[] pub) throws Exception {
    try {
      org.bouncycastle.math.ec.ECPoint point = DOMAIN_PARAMS.getCurve().decodePoint(pub);
      ECPublicKeyParameters pubKey = new ECPublicKeyParameters(point, DOMAIN_PARAMS);
      signer.init(false, new ParametersWithID(pubKey, DEFAULT_ID));
    } catch (Exception e) {
      throw new InvalidKeyException(e);
    }
  }

  @Override
  public void setPrvKey(byte[] prv) throws Exception {
    try {
      BigInteger d = new BigInteger(1, prv);
      ECPrivateKeyParameters prvKey = new ECPrivateKeyParameters(d, DOMAIN_PARAMS);
      signer.init(true, new ParametersWithID(prvKey, DEFAULT_ID));
    } catch (Exception e) {
      throw new InvalidKeyException(e);
    }
  }

  @Override
  public void update(byte[] foo) throws Exception {
    try {
      signer.update(foo, 0, foo.length);
    } catch (Exception e) {
      throw new SignatureException(e);
    }
  }

  @Override
  public byte[] sign() throws Exception {
    try {
      return signer.generateSignature();
    } catch (Exception e) {
      throw new SignatureException(e);
    }
  }

  @Override
  public boolean verify(byte[] sig) throws Exception {
    // Unwrap SSH signature envelope: [string "sm2"][string raw_sig]
    if (sig.length > 4) {
      int prefixLen = ((sig[0] & 0xff) << 24) | ((sig[1] & 0xff) << 16) | ((sig[2] & 0xff) << 8)
          | (sig[3] & 0xff);
      if (prefixLen > 0 && prefixLen + 4 <= sig.length) {
        Buffer buf = new Buffer(sig);
        String type = new String(buf.getString(), StandardCharsets.UTF_8);
        if (type.equals(KEY_TYPE)) {
          sig = buf.getString();
        }
      }
    }
    try {
      return signer.verifySignature(sig);
    } catch (Exception e) {
      throw new SignatureException(e);
    }
  }
}
