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
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

public class ECDHSM2 implements ECDH {

  /*
   * Identity bytes used by the OpenEuler sm2-sm3 KEX implementation. These are raw byte values
   * {1,2,...,8,1,2,...,8}, matching the C initializer in SM2KAP_compute_key() in kexsm2.c.
   */
  private static final byte[] SM2_KAP_ID = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};

  private static final ECDomainParameters DOMAIN_PARAMS;
  private static final byte[] CURVE_A_BYTES;
  private static final byte[] CURVE_B_BYTES;
  private static final byte[] CURVE_GX_BYTES;
  private static final byte[] CURVE_GY_BYTES;

  static {
    X9ECParameters x9 = GMNamedCurves.getByName("sm2p256v1");
    DOMAIN_PARAMS =
        new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
    ECPoint G = x9.getG().normalize();
    CURVE_A_BYTES = toBytes32(x9.getCurve().getA().toBigInteger());
    CURVE_B_BYTES = toBytes32(x9.getCurve().getB().toBigInteger());
    CURVE_GX_BYTES = toBytes32(G.getAffineXCoord().toBigInteger());
    CURVE_GY_BYTES = toBytes32(G.getAffineYCoord().toBigInteger());
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
    Q_array = pubKey.getQ().getEncoded(false); // uncompressed: 0x04 || x || y
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
    // Reconstruct peer's ephemeral public key Q_peer from (x, y) coordinates
    byte[] point = new byte[1 + r.length + s.length];
    point[0] = 0x04;
    System.arraycopy(r, 0, point, 1, r.length);
    System.arraycopy(s, 0, point, 1 + r.length, s.length);
    ECPoint Q_peer = DOMAIN_PARAMS.getCurve().decodePoint(point).normalize();

    /*
     * Manual SM2 KAP (GM/T 0003.3) matching OpenEuler's SM2KAP_compute_key() in kexsm2.c.
     *
     * Degenerate configuration: static key == ephemeral key for both parties.
     *
     * Client (initiator, server=0): w = 127 (for 256-bit curve: (256+1)/2 - 1) Xs_bar = 2^w +
     * (x(Q_self) mod 2^w) Xp_bar = 2^w + (x(Q_peer) mod 2^w) t = (d * Xs_bar + d) mod n = d * (1 +
     * Xs_bar) mod n U = t * (Xp_bar * Q_peer + Q_peer) K = KDF(xU || yU || ZA || ZB, 32)
     *
     * where ZA = SM3(entlen || id || a || b || Gx || Gy || x(Q_self) || y(Q_self)) ZB = SM3(entlen
     * || id || a || b || Gx || Gy || x(Q_peer) || y(Q_peer)) KDF(Z, 32) = SM3(Z ||
     * 0x00000001)[0:32]
     */
    BigInteger d = privateKey.getD();
    BigInteger n = DOMAIN_PARAMS.getN();
    ECPoint Q_self = DOMAIN_PARAMS.getG().multiply(d).normalize();

    // w = 127 for sm2p256v1 (256-bit curve)
    BigInteger two_power_w = BigInteger.ONE.shiftLeft(127);
    BigInteger mask = two_power_w.subtract(BigInteger.ONE); // 2^127 - 1

    BigInteger x_self = Q_self.getAffineXCoord().toBigInteger();
    BigInteger x_peer = Q_peer.getAffineXCoord().toBigInteger();

    // Xs_bar = 2^127 + (x_self mod 2^127)
    BigInteger Xs_bar = two_power_w.add(x_self.and(mask));
    // Xp_bar = 2^127 + (x_peer mod 2^127)
    BigInteger Xp_bar = two_power_w.add(x_peer.and(mask));

    // t = (Xs_bar * d + d) mod n [degenerate: static_priv = eph_priv = d]
    // cofactor h = 1 for sm2p256v1, so no h multiplication needed
    BigInteger t = Xs_bar.multiply(d).add(d).mod(n);

    // U = t * (Xp_bar * Q_peer + Q_peer)
    ECPoint U = Q_peer.multiply(Xp_bar).add(Q_peer).multiply(t).normalize();

    if (U.isInfinity()) {
      throw new Exception("SM2 KAP: shared point is at infinity");
    }

    byte[] xU = toBytes32(U.getAffineXCoord().toBigInteger());
    byte[] yU = toBytes32(U.getAffineYCoord().toBigInteger());

    byte[] ZA = computeZ(SM2_KAP_ID, Q_self);
    byte[] ZB = computeZ(SM2_KAP_ID, Q_peer);

    // KDF input = xU || yU || ZA || ZB
    byte[] kdfInput = new byte[xU.length + yU.length + ZA.length + ZB.length];
    int off = 0;
    System.arraycopy(xU, 0, kdfInput, off, xU.length);
    off += xU.length;
    System.arraycopy(yU, 0, kdfInput, off, yU.length);
    off += yU.length;
    System.arraycopy(ZA, 0, kdfInput, off, ZA.length);
    off += ZA.length;
    System.arraycopy(ZB, 0, kdfInput, off, ZB.length);

    return kdf(kdfInput, 32);
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

  /** Compute SM2 Z value: SM3(entlen || id || a || b || Gx || Gy || xA || yA) */
  private static byte[] computeZ(byte[] id, ECPoint pub) {
    SM3Digest sm3 = new SM3Digest();
    // entlen: bit-length of id as 2-byte big-endian
    int entlen = id.length * 8;
    sm3.update((byte) (entlen >> 8));
    sm3.update((byte) (entlen & 0xff));
    sm3.update(id, 0, id.length);
    sm3.update(CURVE_A_BYTES, 0, CURVE_A_BYTES.length);
    sm3.update(CURVE_B_BYTES, 0, CURVE_B_BYTES.length);
    sm3.update(CURVE_GX_BYTES, 0, CURVE_GX_BYTES.length);
    sm3.update(CURVE_GY_BYTES, 0, CURVE_GY_BYTES.length);
    ECPoint p = pub.normalize();
    byte[] xA = toBytes32(p.getAffineXCoord().toBigInteger());
    byte[] yA = toBytes32(p.getAffineYCoord().toBigInteger());
    sm3.update(xA, 0, xA.length);
    sm3.update(yA, 0, yA.length);
    byte[] z = new byte[32];
    sm3.doFinal(z, 0);
    return z;
  }

  /** GM/T 0003 KDF: SM3(Z || counter_bigendian), counter starts at 1 */
  private static byte[] kdf(byte[] data, int keyLen) {
    byte[] result = new byte[keyLen];
    int offset = 0;
    int counter = 1;
    SM3Digest sm3 = new SM3Digest();
    while (offset < keyLen) {
      sm3.reset();
      sm3.update(data, 0, data.length);
      sm3.update((byte) (counter >> 24));
      sm3.update((byte) (counter >> 16));
      sm3.update((byte) (counter >> 8));
      sm3.update((byte) counter);
      byte[] hash = new byte[32];
      sm3.doFinal(hash, 0);
      int copy = Math.min(32, keyLen - offset);
      System.arraycopy(hash, 0, result, offset, copy);
      offset += copy;
      counter++;
    }
    return result;
  }

  /**
   * Encode a BigInteger as exactly 32 bytes (big-endian, zero-padded or truncated from sign byte)
   */
  private static byte[] toBytes32(BigInteger val) {
    byte[] bytes = val.toByteArray();
    byte[] result = new byte[32];
    if (bytes.length <= 32) {
      System.arraycopy(bytes, 0, result, 32 - bytes.length, bytes.length);
    } else {
      // strip leading zero sign byte(s)
      System.arraycopy(bytes, bytes.length - 32, result, 0, 32);
    }
    return result;
  }
}
