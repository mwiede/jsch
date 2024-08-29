package com.jcraft.jsch;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class PktSize128IT extends AbstractBufferMargin {

  public PktSize128IT() {
    super(128);
  }

  @ParameterizedTest
  @CsvSource(value = {
      // 16 byte tag (MAC doesn't matter)
      "aes128-gcm@openssh.com,hmac-sha1,none", "aes128-gcm@openssh.com,hmac-sha1,zlib@openssh.com",
      // 12 byte MAC
      "aes128-ctr,hmac-md5-96,none", "aes128-ctr,hmac-md5-96,zlib@openssh.com",
      // 16 byte MAC
      "aes128-ctr,hmac-md5,none", "aes128-ctr,hmac-md5,zlib@openssh.com",
      // 20 byte MAC
      "aes128-ctr,hmac-sha1,none", "aes128-ctr,hmac-sha1,zlib@openssh.com"})
  public void testSftp(String cipher, String mac, String compression) throws Exception {
    doTestSftp(cipher, mac, compression);
  }

  @ParameterizedTest
  @CsvSource(value = {
      // 16 byte tag (MAC doesn't matter)
      "aes128-gcm@openssh.com,hmac-sha1,none", "aes128-gcm@openssh.com,hmac-sha1,zlib@openssh.com",
      // 12 byte MAC
      "aes128-ctr,hmac-md5-96,none", "aes128-ctr,hmac-md5-96,zlib@openssh.com",
      // 16 byte MAC
      "aes128-ctr,hmac-md5,none", "aes128-ctr,hmac-md5,zlib@openssh.com",
      // 20 byte MAC
      "aes128-ctr,hmac-sha1,none", "aes128-ctr,hmac-sha1,zlib@openssh.com",
      // 32 byte MAC
      "aes128-ctr,hmac-sha2-256,none", "aes128-ctr,hmac-sha2-256,zlib@openssh.com"})
  public void testScp(String cipher, String mac, String compression) throws Exception {
    doTestScp(cipher, mac, compression);
  }
}
