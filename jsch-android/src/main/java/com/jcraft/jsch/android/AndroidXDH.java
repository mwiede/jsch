// SPDX-License-Identifier: BSD-3-Clause
package com.jcraft.jsch.android;

import java.security.InvalidKeyException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;

public class AndroidXDH implements com.jcraft.jsch.XDH {
  private static final String X25519 = "X25519";
  private static final byte[] X25519_PREFIX = {
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
  };

  private com.jcraft.jsch.XDH fallback;
  private KeyAgreement agreement;
  private KeyFactory keyFactory;
  private byte[] publicKey;

  @Override
  public void init(String name, int keylen) throws Exception {
    if (!X25519.equals(name) || keylen != 32) {
      useBouncyCastle(name, keylen);
      return;
    }
    try {
      Provider provider = AndroidJSch.provider(X25519, "KeyAgreement", "KeyPairGenerator", "KeyFactory");
      KeyPairGenerator generator = KeyPairGenerator.getInstance(X25519, provider);
      KeyPair pair = generator.generateKeyPair();
      byte[] encoded = pair.getPublic().getEncoded();
      if (encoded == null || encoded.length != X25519_PREFIX.length + 32
          || !Arrays.equals(Arrays.copyOf(encoded, X25519_PREFIX.length), X25519_PREFIX)) {
        throw new InvalidKeyException("Unexpected X25519 public key encoding");
      }
      publicKey = Arrays.copyOfRange(encoded, X25519_PREFIX.length, encoded.length);
      keyFactory = KeyFactory.getInstance(X25519, provider);
      agreement = KeyAgreement.getInstance(X25519, provider);
      agreement.init(pair.getPrivate());
    } catch (GeneralSecurityException e) {
      useBouncyCastle(name, keylen);
    }
  }

  private void useBouncyCastle(String name, int keylen) throws Exception {
    fallback = new com.jcraft.jsch.bc.XDH();
    fallback.init(name, keylen);
  }

  @Override
  public byte[] getQ() throws Exception {
    return fallback != null ? fallback.getQ() : publicKey.clone();
  }

  @Override
  public byte[] getSecret(byte[] peer) throws Exception {
    if (fallback != null) {
      return fallback.getSecret(peer);
    }
    if (!validate(peer)) {
      throw new InvalidKeyException("X25519 public key must be 32 bytes");
    }
    byte[] encoded = Arrays.copyOf(X25519_PREFIX, X25519_PREFIX.length + 32);
    System.arraycopy(peer, 0, encoded, X25519_PREFIX.length, 32);
    PublicKey key = keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
    agreement.doPhase(key, true);
    return agreement.generateSecret();
  }

  @Override
  public boolean validate(byte[] peer) throws Exception {
    return fallback != null ? fallback.validate(peer) : peer.length == 32;
  }
}
