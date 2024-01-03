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

import com.jcraft.jsch.KEM;
import com.jcraft.jsch.annotations.SuppressForbiddenApi;
import java.lang.reflect.Constructor;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.ntruprime.*;

public class SNTRUP761 implements KEM {
  SNTRUPrimeKEMExtractor extractor;
  SNTRUPrimePublicKeyParameters publicKey;

  @Override
  public void init() throws Exception {
    SNTRUPrimeKeyPairGenerator kpg = new SNTRUPrimeKeyPairGenerator();
    kpg.init(new SNTRUPrimeKeyGenerationParameters(new SecureRandom(), sntrup761()));
    AsymmetricCipherKeyPair kp = kpg.generateKeyPair();
    extractor = new SNTRUPrimeKEMExtractor((SNTRUPrimePrivateKeyParameters) kp.getPrivate());
    publicKey = (SNTRUPrimePublicKeyParameters) kp.getPublic();
  }

  @Override
  public byte[] getPublicKey() throws Exception {
    return publicKey.getEncoded();
  }

  @Override
  public byte[] decapsulate(byte[] encapsulation) throws Exception {
    return extractor.extractSecret(encapsulation);
  }

  // Bouncy Castle before 1.78 defines sharedKeyBytes differently than OpenSSH (16 instead of 32)
  // https://github.com/bcgit/bc-java/issues/1554
  // https://github.com/bcgit/bc-java/commit/db3ae60
  @SuppressForbiddenApi("jdk-reflection")
  static SNTRUPrimeParameters sntrup761() throws Exception {
    if (SNTRUPrimeParameters.sntrup761.getSessionKeySize() == 32 * 8) {
      return SNTRUPrimeParameters.sntrup761;
    }
    Constructor<SNTRUPrimeParameters> c =
        SNTRUPrimeParameters.class.getDeclaredConstructor(String.class, int.class, int.class,
            int.class, int.class, int.class, int.class, int.class, int.class);
    c.setAccessible(true);
    return c.newInstance("sntrup761", 761, 4591, 286, 1158, 1007, 1158, 1763, 32);
  }
}
