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
import com.jcraft.jsch.KDF;
import java.util.Map;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public class Argon2 implements KDF {
  private Argon2BytesGenerator generator;

  @Override
  public void initWithPPKv3Header(Map<String, String> header) throws Exception {
    try {
      String argonTypeStr = header.get("Key-Derivation");
      String saltStr = header.get("Argon2-Salt");
      if (argonTypeStr == null || saltStr == null
          || (saltStr != null && saltStr.length() % 2 != 0)) {
        throw new JSchException("Invalid argon2 params.");
      }

      int type;
      switch (argonTypeStr) {
        case "Argon2d":
          type = Argon2Parameters.ARGON2_d;
          break;
        case "Argon2i":
          type = Argon2Parameters.ARGON2_i;
          break;
        case "Argon2id":
          type = Argon2Parameters.ARGON2_id;
          break;
        default:
          throw new JSchException("Invalid argon2 params.");
      }

      int memory = Integer.parseInt(header.get("Argon2-Memory"));
      int passes = Integer.parseInt(header.get("Argon2-Passes"));
      int parallelism = Integer.parseInt(header.get("Argon2-Parallelism"));
      byte[] salt = new byte[saltStr.length() / 2];
      for (int i = 0; i < salt.length; i++) {
        int j = i * 2;
        salt[i] = (byte) Integer.parseInt(saltStr.substring(j, j + 2), 16);
      }

      Argon2Parameters params =
          new Argon2Parameters.Builder(type).withSalt(salt).withAdditional(new byte[0])
              .withSecret(new byte[0]).withIterations(passes).withMemoryAsKB(memory)
              .withParallelism(parallelism).withVersion(Argon2Parameters.ARGON2_VERSION_13).build();
      generator = new Argon2BytesGenerator();
      generator.init(params);
    } catch (NumberFormatException e) {
      throw new JSchException("Invalid argon2 params.", e);
    }
  }

  @Override
  public byte[] getKey(byte[] pass, int size) {
    byte[] key = new byte[size];
    generator.generateBytes(pass, key);
    return key;
  }
}
