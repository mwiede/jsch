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

import java.security.*;
import org.bouncycastle.crypto.params.*;

public class KeyPairGenEdDSA implements com.jcraft.jsch.KeyPairGenEdDSA {
  byte[] prv; // private
  byte[] pub; // public
  int keylen;
  String name;

  @Override
  public void init(String name, int keylen) throws Exception {
    if (!name.equals("Ed25519") && !name.equals("Ed448")) {
      throw new NoSuchAlgorithmException("invalid curve " + name);
    }
    this.keylen = keylen;
    this.name = name;

    if (name.equals("Ed25519")) {
      Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(new SecureRandom());
      pub = privateKey.generatePublicKey().getEncoded();
      prv = privateKey.getEncoded();
    } else {
      Ed448PrivateKeyParameters privateKey = new Ed448PrivateKeyParameters(new SecureRandom());
      pub = privateKey.generatePublicKey().getEncoded();
      prv = privateKey.getEncoded();
    }
  }

  @Override
  public byte[] getPrv() {
    return prv;
  }

  @Override
  public byte[] getPub() {
    return pub;
  }

  @Override
  public void init(String name, byte[] prv) throws Exception {
    if (!name.equals("Ed25519") && !name.equals("Ed448")) {
      throw new NoSuchAlgorithmException("invalid curve " + name);
    }
    this.name = name;

    if (name.equals("Ed25519")) {
      Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(prv);
      pub = privateKey.generatePublicKey().getEncoded();
      this.prv = privateKey.getEncoded();
    } else {
      Ed448PrivateKeyParameters privateKey = new Ed448PrivateKeyParameters(prv);
      pub = privateKey.generatePublicKey().getEncoded();
      this.prv = privateKey.getEncoded();
    }
    this.keylen = this.prv.length;
  }
}
