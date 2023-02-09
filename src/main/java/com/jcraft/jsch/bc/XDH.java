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

import java.security.*;
import java.util.Arrays;
import org.bouncycastle.crypto.params.*;

public class XDH implements com.jcraft.jsch.XDH {
  byte[] Q_array;
  Object privateKey;
  int keylen;
  String name;

  @Override
  public void init(String name, int keylen) throws Exception {
    if (!name.equals("X25519") && !name.equals("X448")) {
      throw new NoSuchAlgorithmException("invalid curve " + name);
    }
    this.keylen = keylen;
    this.name = name;
    if (name.equals("X25519")) {
      X25519PrivateKeyParameters privateKey = new X25519PrivateKeyParameters(new SecureRandom());
      Q_array = privateKey.generatePublicKey().getEncoded();
      this.privateKey = privateKey;
    } else {
      X448PrivateKeyParameters privateKey = new X448PrivateKeyParameters(new SecureRandom());
      Q_array = privateKey.generatePublicKey().getEncoded();
      this.privateKey = privateKey;
    }
  }

  @Override
  public byte[] getQ() throws Exception {
    return Q_array;
  }

  @Override
  public byte[] getSecret(byte[] Q) throws Exception {
    byte[] secret = new byte[keylen];
    if (name.equals("X25519")) {
      X25519PublicKeyParameters publicKey = null;
      try {
        publicKey = new X25519PublicKeyParameters(Q, 0);
      } catch (Exception e) {
        throw new InvalidKeyException(e);
      }

      X25519PrivateKeyParameters privateKey = (X25519PrivateKeyParameters) this.privateKey;
      try {
        privateKey.generateSecret(publicKey, secret, 0);
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
    } else {
      X448PublicKeyParameters publicKey = null;
      try {
        publicKey = new X448PublicKeyParameters(Q, 0);
      } catch (Exception e) {
        throw new InvalidKeyException(e);
      }

      X448PrivateKeyParameters privateKey = (X448PrivateKeyParameters) this.privateKey;
      try {
        privateKey.generateSecret(publicKey, secret, 0);
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
    }
    return secret;
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
}
