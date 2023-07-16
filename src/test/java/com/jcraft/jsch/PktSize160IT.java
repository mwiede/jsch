package com.jcraft.jsch;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class PktSize160IT extends AbstractBufferMargin {

  public PktSize160IT() {
    super(160);
  }

  @ParameterizedTest
  @CsvSource(value = {
      // 32 byte MAC
      "aes128-ctr,hmac-sha2-256,none", "aes128-ctr,hmac-sha2-256,zlib@openssh.com"})
  public void testSftp(String cipher, String mac, String compression) throws Exception {
    doTestSftp(cipher, mac, compression);
  }

  @ParameterizedTest
  @CsvSource(value = {
      // 64 byte MAC
      "aes128-ctr,hmac-sha2-512,none", "aes128-ctr,hmac-sha2-512,zlib@openssh.com"})
  public void testScp(String cipher, String mac, String compression) throws Exception {
    doTestScp(cipher, mac, compression);
  }
}
