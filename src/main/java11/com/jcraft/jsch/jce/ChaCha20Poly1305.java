/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2008-2018 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright 
     notice, this list of conditions and the following disclaimer in 
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package com.jcraft.jsch.jce;

import com.jcraft.jsch.Cipher;
import com.jcraft.jsch.openjax.Poly1305;
import java.nio.ByteBuffer;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.spec.*;

public class ChaCha20Poly1305 implements Cipher{
  //Actually the block size, not IV size
  private static final int ivsize=8;
  //Actually the key size, not block size
  private static final int bsize=64;
  private static final int tagsize=16;
  private javax.crypto.Cipher header_cipher;
  private javax.crypto.Cipher main_cipher;
  private SecretKeySpec K_1_spec;
  private SecretKeySpec K_2_spec;
  private int mode;
  private Poly1305 poly1305;
  public int getIVSize(){return ivsize;}
  public int getBlockSize(){return bsize;}
  public int getTagSize(){return tagsize;}
  public void init(int mode, byte[] key, byte[] iv) throws Exception{
    byte[] tmp;
    if(key.length>bsize){
      tmp=new byte[bsize];
      System.arraycopy(key, 0, tmp, 0, tmp.length);
      key=tmp;
    }
    byte[] K_1=new byte[bsize/2];
    byte[] K_2=new byte[bsize/2];
    System.arraycopy(key, bsize/2, K_1, 0, bsize/2);
    System.arraycopy(key, 0, K_2, 0, bsize/2);
    this.mode=((mode==ENCRYPT_MODE)?
                javax.crypto.Cipher.ENCRYPT_MODE:
                javax.crypto.Cipher.DECRYPT_MODE);
    try{
      K_1_spec=new SecretKeySpec(K_1, "ChaCha20");
      K_2_spec=new SecretKeySpec(K_2, "ChaCha20");
      header_cipher=javax.crypto.Cipher.getInstance("ChaCha20");
      main_cipher=javax.crypto.Cipher.getInstance("ChaCha20");
    }
    catch(Exception e){
      header_cipher=null;
      main_cipher=null;
      K_1_spec=null;
      K_2_spec=null;
      throw e;
    }
  }
  public void update(int foo) throws Exception{
    ByteBuffer nonce=ByteBuffer.allocate(12);
    nonce.putLong(4, foo);
    header_cipher.init(this.mode, K_1_spec, new ChaCha20ParameterSpec(nonce.array(), 0));
    main_cipher.init(this.mode, K_2_spec, new ChaCha20ParameterSpec(nonce.array(), 0));
    // Trying to reinit the cipher again with same nonce results in InvalidKeyException
    // So just read entire first 64-byte block, which should increment global counter from 0->1
    byte[] poly_key = new byte[32];
    byte[] discard = new byte[32];
    main_cipher.update(poly_key, 0, 32, poly_key, 0);
    main_cipher.update(discard, 0, 32, discard, 0);
    poly1305 = new Poly1305(poly_key);
  }
  public void update(byte[] foo, int s1, int len, byte[] bar, int s2) throws Exception{
    header_cipher.update(foo, s1, len, bar, s2);
  }
  public void updateAAD(byte[] foo, int s1, int len) throws Exception{
  }
  public void doFinal(byte[] foo, int s1, int len, byte[] bar, int s2) throws Exception{
    if(this.mode==javax.crypto.Cipher.DECRYPT_MODE){
      byte[] actual_tag = new byte[tagsize];
      System.arraycopy(foo, len, actual_tag, 0, tagsize);
      byte[] expected_tag = new byte[tagsize];
      poly1305.update(foo, s1, len).finish(expected_tag, 0);
      if(!arraysequals(actual_tag, expected_tag)){
        throw new AEADBadTagException("Tag mismatch");
      }
    }

    main_cipher.update(foo, s1+4, len-4, bar, s2+4);

    if(this.mode==javax.crypto.Cipher.ENCRYPT_MODE){
      poly1305.update(bar, s2, len).finish(bar, len);
    }
  }
  public boolean isCBC(){return false; }
  public boolean isAEAD(){return true; }
  public boolean isChaCha20(){return true; }

  private static boolean arraysequals(byte[] a, byte[] b){
    if(a.length!=b.length) return false;
    int res=0;
    for(int i=0; i<a.length; i++){
      res|=a[i]^b[i];
    }
    return res==0;
  }
}
