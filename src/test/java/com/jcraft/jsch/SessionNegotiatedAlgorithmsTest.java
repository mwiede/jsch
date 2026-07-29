package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the Session accessors reporting the algorithms negotiated during key exchange. We craft
 * the I_S/I_C (server/client KEXINIT payloads), run the negotiation over them and store the outcome
 * the same way receive_newkeys() publishes it, then check what each accessor reports.
 */
class SessionNegotiatedAlgorithmsTest {

  private static Session newSession() throws Exception {
    // Reuse pattern from existing tests: username null -> defaults to system user.
    return new Session(new JSch(), null, null, 0);
  }

  /** Builds a SSH_MSG_KEXINIT payload carrying the ten given name-lists. */
  private static byte[] buildKexInit(String... proposals) {
    Buffer buf = new Buffer();
    buf.putByte((byte) 20); // SSH_MSG_KEXINIT
    buf.putByte(new byte[16]); // cookie
    for (String proposal : proposals) {
      buf.putString(Util.str2byte(proposal));
    }
    buf.putByte((byte) 0); // first_kex_packet_follows
    buf.putInt(0); // reserved
    byte[] payload = new byte[buf.getLength()];
    buf.getByte(payload);
    return payload;
  }

  @Test
  @DisplayName("accessors return null before any key exchange has been performed")
  void notNegotiatedYet() throws Exception {
    Session s = newSession();
    assertNull(s.getKexAlgorithm());
    assertNull(s.getServerHostKeyAlgorithm());
    assertNull(s.getCipherAlgorithmC2S());
    assertNull(s.getCipherAlgorithmS2C());
    assertNull(s.getMacAlgorithmC2S());
    assertNull(s.getMacAlgorithmS2C());
    assertNull(s.getCompressionAlgorithmC2S());
    assertNull(s.getCompressionAlgorithmS2C());
  }

  @Test
  @DisplayName("accessors report the negotiated algorithm of each proposal and direction")
  void negotiatedAlgorithms() throws Exception {
    Session s = newSession();
    // Every proposal names something different, and each direction is deliberately reversed
    // relative to the other, so that a mixed up proposal index cannot go unnoticed.
    byte[] I_C =
        buildKexInit("curve25519-sha256,diffie-hellman-group14-sha256", "ssh-ed25519,rsa-sha2-256",
            "aes128-ctr,aes192-ctr", "aes192-ctr,aes128-ctr", "hmac-sha2-256,hmac-sha1",
            "hmac-sha1,hmac-sha2-256", "none,zlib@openssh.com", "zlib@openssh.com,none", "", "");
    // The server offers the same algorithms in the opposite order, so the assertions below also
    // pin down that the client's preference is the one that wins.
    byte[] I_S =
        buildKexInit("diffie-hellman-group14-sha256,curve25519-sha256", "rsa-sha2-256,ssh-ed25519",
            "aes192-ctr,aes128-ctr", "aes128-ctr,aes192-ctr", "hmac-sha1,hmac-sha2-256",
            "hmac-sha2-256,hmac-sha1", "zlib@openssh.com,none", "none,zlib@openssh.com", "", "");
    s.negotiatedAlgorithms = KeyExchange.guess(s, I_S, I_C);

    assertEquals("curve25519-sha256", s.getKexAlgorithm());
    assertEquals("ssh-ed25519", s.getServerHostKeyAlgorithm());
    assertEquals("aes128-ctr", s.getCipherAlgorithmC2S());
    assertEquals("aes192-ctr", s.getCipherAlgorithmS2C());
    assertEquals("hmac-sha2-256", s.getMacAlgorithmC2S());
    assertEquals("hmac-sha1", s.getMacAlgorithmS2C());
    assertEquals("none", s.getCompressionAlgorithmC2S());
    assertEquals("zlib@openssh.com", s.getCompressionAlgorithmS2C());
  }

  @Test
  @DisplayName("accessors ignore an in-progress negotiation until its keys are put into use")
  void inProgressNegotiationNotReported() throws Exception {
    Session s = newSession();
    // receive_kexinit() stores the negotiation outcome in guess, but it is only published to
    // negotiatedAlgorithms by receive_newkeys() once the algorithms are put into use.
    s.guess = KeyExchange.guess(s,
        buildKexInit("curve25519-sha256", "ssh-ed25519", "aes128-ctr", "aes128-ctr",
            "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""),
        buildKexInit("curve25519-sha256", "ssh-ed25519", "aes128-ctr", "aes128-ctr",
            "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""));

    assertNull(s.getKexAlgorithm());
    assertNull(s.getCipherAlgorithmC2S());
  }

  @Test
  @DisplayName("MAC accessors return null when an AEAD cipher is negotiated")
  void negotiatedAeadCipherHasNoMac() throws Exception {
    Session s = newSession();
    byte[] I_C = buildKexInit("curve25519-sha256", "ssh-ed25519", "aes128-gcm@openssh.com",
        "aes128-gcm@openssh.com", "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", "");
    byte[] I_S = buildKexInit("curve25519-sha256", "ssh-ed25519", "aes128-gcm@openssh.com",
        "aes128-gcm@openssh.com", "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", "");
    s.negotiatedAlgorithms = KeyExchange.guess(s, I_S, I_C);

    assertEquals("aes128-gcm@openssh.com", s.getCipherAlgorithmC2S());
    assertEquals("aes128-gcm@openssh.com", s.getCipherAlgorithmS2C());
    assertNull(s.getMacAlgorithmC2S());
    assertNull(s.getMacAlgorithmS2C());
  }
}
