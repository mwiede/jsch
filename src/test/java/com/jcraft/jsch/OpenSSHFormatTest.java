package com.jcraft.jsch;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OpenSSHFormatTest {
  @Test
  public void decrypt_private_key_in_openssh_format() throws JSchException {
    String encryptedPrivateKey = "" +
        "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
        "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\n" +
        "-----END OPENSSH PRIVATE KEY-----";
    String password = "12345";

    JSch jsch = new JSch();
    KeyPair kpair = KeyPair.load(jsch, encryptedPrivateKey.getBytes(StandardCharsets.UTF_8), null);
    assertTrue(kpair.isEncrypted());
    assertTrue(kpair.decrypt(password));
    assertNotNull(kpair.getPrivateKey());
  }
}
