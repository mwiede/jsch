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

package com.jcraft.jsch.android;

import com.jcraft.jsch.Buffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * EdDSA implementation for Java 8, which is the one Android loads.
 *
 * <p>
 * Android reports Java 8 and ignores {@code META-INF/versions}, so it never sees the Java 15
 * implementation. The {@code EdEC} key specs that one uses do not exist at this source level, so
 * the raw SSH key bytes are wrapped in their RFC 8410 encodings and handed to the JCA that way.
 *
 * <p>
 * Where the platform JCA has no EdDSA, {@link #init()} throws and the caller leaves the algorithm
 * unavailable.
 */
abstract class AndroidSignatureEdDSA implements com.jcraft.jsch.SignatureEdDSA {

  private Signature signature;
  private KeyFactory keyFactory;

  abstract String getName();

  abstract String getAlgo();

  abstract int getKeylen();

  @Override
  public void init() throws Exception {
    Provider provider = provider(getAlgo());
    signature = Signature.getInstance(getAlgo(), provider);
    keyFactory = KeyFactory.getInstance(getAlgo(), provider);
  }

  /**
   * Finds a provider offering both services for the algorithm. Asking for each separately is not
   * enough: Android registers an Ed25519 KeyFactory in its key store provider, which only handles
   * key store entries and rejects the raw key material used here. Where no provider offers both,
   * the platform cannot sign with an imported key, and leaving the algorithm unavailable is the
   * right answer.
   */
  private static Provider provider(String algo) throws NoSuchAlgorithmException {
    for (Provider provider : Security.getProviders()) {
      if (provider.getService("Signature", algo) != null
          && provider.getService("KeyFactory", algo) != null) {
        return provider;
      }
    }
    throw new NoSuchAlgorithmException("no provider for " + algo + " Signature and KeyFactory");
  }

  @Override
  public void setPubKey(byte[] publicKeyBytes) throws Exception {
    if (publicKeyBytes.length < getKeylen()) {
      throw new InvalidKeyException(getAlgo() + " public key must be " + getKeylen() + " bytes");
    }
    byte[] spki = concat(spkiPrefix(getAlgo()), Arrays.copyOf(publicKeyBytes, getKeylen()));
    PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(spki));
    signature.initVerify(pubKey);
  }

  @Override
  public void setPrvKey(byte[] bytes) throws Exception {
    if (bytes.length < getKeylen()) {
      throw new InvalidKeyException(getAlgo() + " private key must be " + getKeylen() + " bytes");
    }
    byte[] pkcs8 = concat(pkcs8Prefix(getAlgo()), Arrays.copyOf(bytes, getKeylen()));
    PrivateKey prvKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    signature.initSign(prvKey);
  }

  @Override
  public byte[] sign() throws Exception {
    return signature.sign();
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

  // RFC 8410 public-key DER prefix for the raw key bytes.
  private static byte[] spkiPrefix(String algo) {
    if (algo.equals("Ed25519")) {
      return fromHex("302a300506032b6570032100");
    }
    return fromHex("3043300506032b6571033a00");
  }

  // RFC 8410 private-key DER prefix for the raw key bytes.
  private static byte[] pkcs8Prefix(String algo) {
    if (algo.equals("Ed25519")) {
      return fromHex("302e020100300506032b657004220420");
    }
    return fromHex("3047020100300506032b6571043b0439");
  }

  private static byte[] fromHex(String hex) {
    byte[] out = new byte[hex.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = new byte[a.length + b.length];
    System.arraycopy(a, 0, out, 0, a.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }
}
