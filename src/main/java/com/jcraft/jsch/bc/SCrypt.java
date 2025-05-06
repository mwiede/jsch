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
import com.jcraft.jsch.asn1.ASN1;
import com.jcraft.jsch.asn1.ASN1Exception;

public class SCrypt implements KDF {
  private Class<?> ignore;
  private byte[] salt;
  private int cost;
  private int blocksize;
  private int parallel;

  @Override
  public void initWithASN1(byte[] asn1) throws Exception {
    try {
      ignore = org.bouncycastle.crypto.generators.SCrypt.class;

      ASN1 content = new ASN1(asn1);
      if (!content.isSEQUENCE()) {
        throw new ASN1Exception();
      }
      ASN1[] contents = content.getContents();
      if (contents.length < 4 || contents.length > 5) {
        throw new ASN1Exception();
      }
      if (!contents[0].isOCTETSTRING()) {
        throw new ASN1Exception();
      }
      if (!contents[1].isINTEGER()) {
        throw new ASN1Exception();
      }
      if (!contents[2].isINTEGER()) {
        throw new ASN1Exception();
      }
      if (!contents[3].isINTEGER()) {
        throw new ASN1Exception();
      }
      if (contents.length > 4 && !contents[4].isINTEGER()) {
        throw new ASN1Exception();
      }

      salt = contents[0].getContent();
      cost = ASN1.parseASN1IntegerAsInt(contents[1].getContent());
      blocksize = ASN1.parseASN1IntegerAsInt(contents[2].getContent());
      parallel = ASN1.parseASN1IntegerAsInt(contents[3].getContent());
    } catch (LinkageError | Exception e) {
      if (e instanceof JSchException)
        throw (JSchException) e;
      if (e instanceof ASN1Exception || e instanceof ArithmeticException)
        throw new JSchException("invalid ASN1", e);
      throw new JSchException("scrypt unavailable", e);
    }
  }

  @Override
  public byte[] getKey(byte[] pass, int size) {
    return org.bouncycastle.crypto.generators.SCrypt.generate(pass, salt, cost, blocksize, parallel,
        size);
  }
}
