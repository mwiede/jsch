/*
 * Copyright (c) 2013-2018 ymnk, JCraft,Inc. All rights reserved.
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

import com.jcraft.jsch.JSchException;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public class Argon2 implements com.jcraft.jsch.Argon2 {
  private Argon2BytesGenerator generator;

  @Override
  public void init(byte[] salt, int iteration, int type, byte[] additional, byte[] secret,
      int memory, int parallelism, int version) throws Exception {
    switch (type) {
      case com.jcraft.jsch.Argon2.ARGON2D:
        type = Argon2Parameters.ARGON2_d;
        break;
      case com.jcraft.jsch.Argon2.ARGON2I:
        type = Argon2Parameters.ARGON2_i;
        break;
      case com.jcraft.jsch.Argon2.ARGON2ID:
        type = Argon2Parameters.ARGON2_id;
        break;
      default:
        throw new JSchException("Invalid argon2 type.");
    }

    switch (version) {
      case com.jcraft.jsch.Argon2.V10:
        version = Argon2Parameters.ARGON2_VERSION_10;
        break;
      case com.jcraft.jsch.Argon2.V13:
        version = Argon2Parameters.ARGON2_VERSION_13;
        break;
      default:
        throw new JSchException("Invalid argon2 version.");
    }

    try {
      Argon2Parameters params = new Argon2Parameters.Builder(type).withSalt(salt)
          .withAdditional(additional).withSecret(secret).withIterations(iteration)
          .withMemoryAsKB(memory).withParallelism(parallelism).withVersion(version).build();
      generator = new Argon2BytesGenerator();
      generator.init(params);
    } catch (NoClassDefFoundError e) {
      throw new JSchException("argon2 unavailable", e);
    }
  }

  @Override
  public byte[] getKey(byte[] pass, int size) {
    byte[] key = new byte[size];
    generator.generateBytes(pass, key);
    return key;
  }
}
