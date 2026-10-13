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

package com.jcraft.jsch;

/**
 * SM2 key pair. Public key blob format (per OpenEuler openssh extension):
 *
 * <pre>
 *   string "sm2"       (key type)
 *   string "sm2"       (curve name)
 *   string ecPoint     (uncompressed 04 || x || y)
 * </pre>
 *
 * Signature blob format:
 *
 * <pre>
 *   string "sm2"       (algorithm identifier)
 *   string rawSig      (raw DER signature bytes from SM2Signer)
 * </pre>
 *
 * Private key is loaded from SEC1 PEM (BEGIN EC PRIVATE KEY) with OID 1.2.156.10197.1.301.
 */
class KeyPairSM2 extends KeyPair {

  // DER encoding of OID 1.2.156.10197.1.301 (sm2p256v1): 06 08 2a 81 1c cf 55 01 82 2d
  static final byte[] SM2_OID = {(byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x81, (byte) 0x1c,
      (byte) 0xcf, (byte) 0x55, (byte) 0x01, (byte) 0x82, (byte) 0x2d};

  private static final byte[] KEY_TYPE_BYTES = Util.str2byte("sm2");
  private static final byte[] begin = Util.str2byte("-----BEGIN EC PRIVATE KEY-----");
  private static final byte[] end = Util.str2byte("-----END EC PRIVATE KEY-----");

  private byte[] r_array;
  private byte[] s_array;
  private byte[] prv_array;

  KeyPairSM2(JSch.InstanceLogger instLogger) {
    super(instLogger);
  }

  /** Construct from a public key blob (used when loading public key file). */
  KeyPairSM2(JSch.InstanceLogger instLogger, byte[] pubkey) {
    super(instLogger);
    if (pubkey != null) {
      Buffer buf = new Buffer(pubkey);
      buf.getString(); // "sm2" (key type)
      buf.getString(); // "sm2" (curve name)
      byte[] ecPoint = buf.getString();
      byte[][] r_s = KeyPairECDSA.fromPoint(ecPoint);
      r_array = r_s[0];
      s_array = r_s[1];
    }
  }

  @Override
  void generate(int key_size) throws JSchException {
    throw new JSchException("SM2 key generation not supported");
  }

  @Override
  byte[] getBegin() {
    return begin;
  }

  @Override
  byte[] getEnd() {
    return end;
  }

  @Override
  boolean parse(byte[] plain) {
    // Parse SEC1 ECPrivateKey: SEQUENCE { INTEGER(1), OCTETSTRING(prv), [0] OID, [1] BIT STRING }
    // Uses the same length-decoding pattern as KeyPairECDSA.parse().
    try {
      int index = 0;
      int length;

      if (plain[index] != 0x30)
        return false;
      index++; // SEQUENCE
      length = plain[index++] & 0xff;
      if ((length & 0x80) != 0) {
        int foo = length & 0x7f;
        length = 0;
        while (foo-- > 0) {
          length = (length << 8) + (plain[index++] & 0xff);
        }
      }

      if (plain[index] != 0x02)
        return false;
      index++; // INTEGER (version = 1)
      length = plain[index++] & 0xff;
      if ((length & 0x80) != 0) {
        int foo = length & 0x7f;
        length = 0;
        while (foo-- > 0) {
          length = (length << 8) + (plain[index++] & 0xff);
        }
      }
      index += length;

      if (plain[index] != 0x04)
        return false;
      index++; // OCTET STRING = private key
      length = plain[index++] & 0xff;
      if ((length & 0x80) != 0) {
        int foo = length & 0x7f;
        length = 0;
        while (foo-- > 0) {
          length = (length << 8) + (plain[index++] & 0xff);
        }
      }
      prv_array = new byte[length];
      System.arraycopy(plain, index, prv_array, 0, length);
      index += length;

      // [0] EXPLICIT — OID (optional, always sm2p256v1 here)
      if (index < plain.length && (plain[index] & 0xff) == 0xa0) {
        index++;
        length = plain[index++] & 0xff;
        if ((length & 0x80) != 0) {
          int foo = length & 0x7f;
          length = 0;
          while (foo-- > 0) {
            length = (length << 8) + (plain[index++] & 0xff);
          }
        }
        index += length; // skip OID bytes
      }

      // [1] EXPLICIT — BIT STRING containing uncompressed EC point (optional)
      if (index < plain.length && (plain[index] & 0xff) == 0xa1) {
        index++;
        length = plain[index++] & 0xff;
        if ((length & 0x80) != 0) {
          int foo = length & 0x7f;
          length = 0;
          while (foo-- > 0) {
            length = (length << 8) + (plain[index++] & 0xff);
          }
        }
        // inner BIT STRING tag 0x03
        if (plain[index] == 0x03) {
          index++;
          int bitLen = plain[index++] & 0xff;
          if ((bitLen & 0x80) != 0) {
            int foo = bitLen & 0x7f;
            bitLen = 0;
            while (foo-- > 0) {
              bitLen = (bitLen << 8) + (plain[index++] & 0xff);
            }
          }
          index++; // unused-bits octet (0x00)
          byte[] point = new byte[bitLen - 1];
          System.arraycopy(plain, index, point, 0, point.length);
          byte[][] r_s = KeyPairECDSA.fromPoint(point);
          r_array = r_s[0];
          s_array = r_s[1];
        }
      }
    } catch (Exception e) {
      if (instLogger.getLogger().isEnabled(Logger.ERROR)) {
        instLogger.getLogger().log(Logger.ERROR, "failed to parse SM2 key", e);
      }
      return false;
    }
    return prv_array != null;
  }

  @Override
  public byte[] getPublicKeyBlob() {
    byte[] cached = super.getPublicKeyBlob();
    if (cached != null)
      return cached;
    if (r_array == null)
      return null;

    byte[][] tmp = new byte[3][];
    tmp[0] = KEY_TYPE_BYTES; // "sm2"
    tmp[1] = KEY_TYPE_BYTES; // "sm2" (curve name)
    tmp[2] = new byte[1 + r_array.length + s_array.length];
    tmp[2][0] = 0x04; // POINT_CONVERSION_UNCOMPRESSED
    System.arraycopy(r_array, 0, tmp[2], 1, r_array.length);
    System.arraycopy(s_array, 0, tmp[2], 1 + r_array.length, s_array.length);
    return Buffer.fromBytes(tmp).buffer;
  }

  @Override
  byte[] getKeyTypeName() {
    return KEY_TYPE_BYTES;
  }

  @Override
  public int getKeyType() {
    return SM2;
  }

  @Override
  public int getKeySize() {
    return 256;
  }

  @Override
  public byte[] getSignature(byte[] data) {
    return getSignature(data, "sm2");
  }

  @Override
  public byte[] getSignature(byte[] data, String alg) {
    try {
      Class<? extends SignatureSM2> c =
          Class.forName(JSch.getConfig("sm2")).asSubclass(SignatureSM2.class);
      SignatureSM2 sm2sig = c.getDeclaredConstructor().newInstance();
      sm2sig.init();
      sm2sig.setPrvKey(prv_array);
      sm2sig.update(data);
      byte[] rawSig = sm2sig.sign();
      byte[][] tmp = new byte[2][];
      tmp[0] = KEY_TYPE_BYTES;
      tmp[1] = rawSig;
      return Buffer.fromBytes(tmp).buffer;
    } catch (Exception e) {
      if (instLogger.getLogger().isEnabled(Logger.ERROR)) {
        instLogger.getLogger().log(Logger.ERROR, "failed to generate SM2 signature", e);
      }
    }
    return null;
  }

  @Override
  public Signature getVerifier() {
    return getVerifier("sm2");
  }

  @Override
  public Signature getVerifier(String alg) {
    try {
      Class<? extends SignatureSM2> c =
          Class.forName(JSch.getConfig("sm2")).asSubclass(SignatureSM2.class);
      SignatureSM2 sm2sig = c.getDeclaredConstructor().newInstance();
      sm2sig.init();
      if (r_array == null && s_array == null && getPublicKeyBlob() != null) {
        Buffer buf = new Buffer(getPublicKeyBlob());
        buf.getString(); // "sm2" type
        buf.getString(); // "sm2" curve
        byte[][] r_s = KeyPairECDSA.fromPoint(buf.getString());
        r_array = r_s[0];
        s_array = r_s[1];
      }
      byte[] ecPoint = new byte[1 + r_array.length + s_array.length];
      ecPoint[0] = 0x04;
      System.arraycopy(r_array, 0, ecPoint, 1, r_array.length);
      System.arraycopy(s_array, 0, ecPoint, 1 + r_array.length, s_array.length);
      sm2sig.setPubKey(ecPoint);
      return sm2sig;
    } catch (Exception e) {
      if (instLogger.getLogger().isEnabled(Logger.ERROR)) {
        instLogger.getLogger().log(Logger.ERROR, "failed to create SM2 verifier", e);
      }
    }
    return null;
  }

  @Override
  public byte[] forSSHAgent() throws JSchException {
    throw new JSchException("SM2 key export to SSH agent not supported");
  }

  @Override
  byte[] getPrivateKey() {
    return null;
  }

  @Override
  byte[] getOpenSSHv1PrivateKeyBlob() {
    return null;
  }

  @Override
  public void dispose() {
    super.dispose();
    Util.bzero(prv_array);
  }
}
