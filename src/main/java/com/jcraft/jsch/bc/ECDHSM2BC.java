/*
 * Copyright (c) 2002-2018 ymnk, JCraft,Inc. All rights reserved.
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

import com.jcraft.jsch.ECDH;
import java.security.SecureRandom;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.SM2KeyExchange;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.SM2KeyExchangePrivateParameters;
import org.bouncycastle.crypto.params.SM2KeyExchangePublicParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * SM2 KAP implementation using BouncyCastle's SM2KeyExchange — for verification only.
 *
 * <p>
 * This class is NOT registered in JSch.java and not used in production. It exists solely to verify
 * the hypothesis that BC's SM2KeyExchange produces the same shared secret as the manual
 * implementation in ECDHSM2, provided calculateKey() is called with kLen in <em>bits</em> (256)
 * rather than bytes (32).
 *
 * <p>
 * The kLen parameter of SM2KeyExchange.calculateKey(int kLen, ...) is in bits. Passing 32 returns
 * only 4 bytes; passing 256 returns the correct 32 bytes.
 */
public class ECDHSM2BC implements ECDH {

  private static final byte[] SM2_KAP_ID = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};

  private static final ECDomainParameters DOMAIN_PARAMS;

  static {
    X9ECParameters x9 = GMNamedCurves.getByName("sm2p256v1");
    DOMAIN_PARAMS =
        new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
  }

  private byte[] Q_array;
  private ECPrivateKeyParameters privateKey;

  @Override
  public void init(int size) throws Exception {
    ECKeyPairGenerator gen = new ECKeyPairGenerator();
    gen.init(new ECKeyGenerationParameters(DOMAIN_PARAMS, new SecureRandom()));
    AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
    privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
    ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();
    Q_array = pubKey.getQ().getEncoded(false);
  }

  /** For testing only: inject a pre-generated key pair instead of generating one randomly. */
  void initForTest(ECPrivateKeyParameters priv, byte[] publicPoint) {
    privateKey = priv;
    Q_array = publicPoint;
  }

  @Override
  public byte[] getQ() throws Exception {
    return Q_array;
  }

  @Override
  public byte[] getSecret(byte[] r, byte[] s) throws Exception {
    byte[] point = new byte[1 + r.length + s.length];
    point[0] = 0x04;
    System.arraycopy(r, 0, point, 1, r.length);
    System.arraycopy(s, 0, point, 1 + r.length, s.length);
    ECPoint remoteQ = DOMAIN_PARAMS.getCurve().decodePoint(point);
    ECPublicKeyParameters peerKey = new ECPublicKeyParameters(remoteQ, DOMAIN_PARAMS);

    SM2KeyExchangePrivateParameters selfParams =
        new SM2KeyExchangePrivateParameters(true, privateKey, privateKey);
    SM2KeyExchangePublicParameters peerParams =
        new SM2KeyExchangePublicParameters(peerKey, peerKey);

    SM2KeyExchange exchange = new SM2KeyExchange();
    exchange.init(new ParametersWithID(selfParams, SM2_KAP_ID));
    // kLen is in BITS: 256 bits = 32 bytes (passing 32 would yield only 4 bytes)
    return exchange.calculateKey(256, new ParametersWithID(peerParams, SM2_KAP_ID));
  }

  @Override
  public boolean validate(byte[] r, byte[] s) throws Exception {
    try {
      byte[] point = new byte[1 + r.length + s.length];
      point[0] = 0x04;
      System.arraycopy(r, 0, point, 1, r.length);
      System.arraycopy(s, 0, point, 1 + r.length, s.length);
      ECPoint p = DOMAIN_PARAMS.getCurve().decodePoint(point);
      return p != null && !p.isInfinity();
    } catch (Exception e) {
      return false;
    }
  }
}
