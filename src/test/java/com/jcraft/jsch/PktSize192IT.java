package com.jcraft.jsch;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class PktSize192IT extends AbstractBufferMargin {

  @ParameterizedTest
  @CsvSource(value = {
      // 64 byte MAC
      "aes128-ctr,hmac-sha2-512,none", "aes128-ctr,hmac-sha2-512,zlib@openssh.com"})
  public void testSftp(String cipher, String mac, String compression) throws Exception {
    doTestSftp(cipher, mac, compression);
  }

  @Override
  protected int maxPktSize() {
    return 192;
  }
}
