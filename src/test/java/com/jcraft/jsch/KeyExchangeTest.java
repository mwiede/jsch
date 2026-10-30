package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class KeyExchangeTest {

  private final Random random = new Random();
  private final KeyExchange kex = new TestKex();

  @Test
  public void testNormalize0() {
    byte[] secret = new byte[0];
    doNormalize(secret);
  }

  @Test
  public void testNormalize1() {
    byte[] secret = new byte[1];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      doNormalize(secret);
    }
  }

  @Test
  public void testNormalize2() {
    byte[] secret = new byte[2];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      for (int j = 0; j <= 0xff; j++) {
        secret[1] = (byte) j;
        doNormalize(secret);
      }
    }
  }

  @Test
  public void testNormalize3() {
    byte[] secret = new byte[3];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      for (int j = 0; j <= 0xff; j++) {
        secret[1] = (byte) j;
        for (int k = 0; k <= 0xff; k++) {
          secret[2] = (byte) k;
          doNormalize(secret);
        }
      }
    }
  }

  @Test
  public void testNormalizeRandom() {
    for (int i = 0; i < 1000000; i++) {
      byte[] secret = new byte[64];
      random.nextBytes(secret);
      doNormalize(secret);
    }
  }

  @Test
  public void testEncodeIntRandom() {
    for (int i = 0; i < 1000000; i++) {
      doEncodeInt(random.nextInt());
    }
  }

  @Test
  public void testEncodeAsMPInt1() {
    byte[] secret = new byte[1];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      doEncodeAsMPInt(secret);
    }
  }

  @Test
  public void testEncodeAsMPInt2() {
    byte[] secret = new byte[2];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      for (int j = 0; j <= 0xff; j++) {
        secret[1] = (byte) j;
        doEncodeAsMPInt(secret);
      }
    }
  }

  @Test
  public void testEncodeAsMPInt3() {
    byte[] secret = new byte[3];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      for (int j = 0; j <= 0xff; j++) {
        secret[1] = (byte) j;
        for (int k = 0; k <= 0xff; k++) {
          secret[2] = (byte) k;
          doEncodeAsMPInt(secret);
        }
      }
    }
  }

  @Test
  public void testEncodeAsMPIntRandom() {
    for (int i = 0; i < 1000000; i++) {
      byte[] secret = new byte[64];
      random.nextBytes(secret);
      doEncodeAsMPInt(secret);
    }
  }

  @Test
  public void testEncodeAsString0() {
    byte[] secret = new byte[0];
    doEncodeAsString(secret);
  }

  @Test
  public void testEncodeAsString1() {
    byte[] secret = new byte[1];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      doEncodeAsString(secret);
    }
  }

  @Test
  public void testEncodeAsString2() {
    byte[] secret = new byte[2];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      for (int j = 0; j <= 0xff; j++) {
        secret[1] = (byte) j;
        doEncodeAsString(secret);
      }
    }
  }

  @Test
  public void testEncodeAsString3() {
    byte[] secret = new byte[3];
    for (int i = 0; i <= 0xff; i++) {
      secret[0] = (byte) i;
      for (int j = 0; j <= 0xff; j++) {
        secret[1] = (byte) j;
        for (int k = 0; k <= 0xff; k++) {
          secret[2] = (byte) k;
          doEncodeAsString(secret);
        }
      }
    }
  }

  @Test
  public void testEncodeAsStringRandom() {
    for (int i = 0; i < 1000000; i++) {
      byte[] secret = new byte[64];
      random.nextBytes(secret);
      doEncodeAsString(secret);
    }
  }

  @Test
  public void testVerifyNegotiatedRsaSignatureAlgorithm() throws Exception {
    JSch jsch = new JSch();
    KeyPair kpair = KeyPair.genKeyPair(jsch, KeyPair.RSA, 2048);
    KeyExchange kex = newVerifyKex(jsch, "rsa-sha2-512", kpair.getPublicKeyBlob());
    byte[] sig_of_H = kpair.getSignature(kex.H, "rsa-sha2-512");
    assertTrue(kex.verify("ssh-rsa", kex.K_S, 4 + 7, sig_of_H));
  }

  @Test
  public void testVerifyRejectsUnnegotiatedRsaSignatureAlgorithm() throws Exception {
    JSch jsch = new JSch();
    KeyPair kpair = KeyPair.genKeyPair(jsch, KeyPair.RSA, 2048);
    KeyExchange kex = newVerifyKex(jsch, "rsa-sha2-512", kpair.getPublicKeyBlob());
    byte[] sig_of_H = kpair.getSignature(kex.H, "ssh-rsa");
    assertThrows(JSchException.class, () -> kex.verify("ssh-rsa", kex.K_S, 4 + 7, sig_of_H));
  }

  @Test
  public void testVerifyRejectsUnnegotiatedHostKeyType() throws Exception {
    JSch jsch = new JSch();
    KeyPair kpair = KeyPair.genKeyPair(jsch, KeyPair.ECDSA, 256);
    KeyExchange kex = newVerifyKex(jsch, "ssh-ed25519", kpair.getPublicKeyBlob());
    byte[] sig_of_H = kpair.getSignature(kex.H);
    assertThrows(JSchException.class,
        () -> kex.verify("ecdsa-sha2-nistp256", kex.K_S, 4 + 19, sig_of_H));
  }

  @ParameterizedTest
  @ValueSource(strings = {"rsa-sha2-256", "rsa-sha2-512"})
  public void testVerifyRsaCertificateAllowsSha2Signature(String signatureAlgorithm)
      throws Exception {
    JSch jsch = new JSch();
    String hostKey = "src/test/resources/certificates/host/ssh_host_rsa_key";
    KeyPair kpair = KeyPair.load(jsch, hostKey);
    byte[] base64 = OpenSshCertificateUtil.extractKeyData(Util.fromFile(hostKey + "-cert.pub"));
    KeyExchange kex = newVerifyKex(jsch, OpenSshCertificateKeyTypes.SSH_RSA_CERT_V01,
        Util.fromBase64(base64, 0, base64.length));
    byte[] sig_of_H = kpair.getSignature(kex.H, signatureAlgorithm);
    assertTrue(kex.verify(OpenSshCertificateKeyTypes.SSH_RSA_CERT_V01, kex.K_S, 0, sig_of_H));
  }

  private KeyExchange newVerifyKex(JSch jsch, String serverHostKeyAlgorithm, byte[] K_S)
      throws Exception {
    Session session = jsch.getSession("user", "host");
    session.guess = new String[KeyExchange.PROPOSAL_MAX];
    session.guess[KeyExchange.PROPOSAL_SERVER_HOST_KEY_ALGS] = serverHostKeyAlgorithm;
    KeyExchange kex = new TestKex();
    kex.session = session;
    kex.K_S = K_S;
    kex.H = new byte[32];
    random.nextBytes(kex.H);
    return kex;
  }

  private void doNormalize(byte[] secret) {
    byte[] expected = normalize(Arrays.copyOf(secret, secret.length));
    byte[] actual = kex.normalize(Arrays.copyOf(secret, secret.length));
    try {
      assertArrayEquals(expected, actual);
    } catch (Exception e) {
      System.out.println("  secret = " + Arrays.toString(secret));
      System.out.println("expected = " + Arrays.toString(expected));
      System.out.println("  actual = " + Arrays.toString(actual));
      throw e;
    }
  }

  // Copy of old implementation
  private static byte[] normalize(byte[] secret) {
    if (secret.length > 1 && secret[0] == 0 && (secret[1] & 0x80) == 0) {
      byte[] tmp = new byte[secret.length - 1];
      System.arraycopy(secret, 1, tmp, 0, tmp.length);
      Util.bzero(secret);
      return normalize(tmp);
    } else {
      return secret;
    }
  }

  private void doEncodeInt(int secret) {
    Buffer b = new Buffer();
    b.putInt(secret);
    byte[] expected = new byte[b.getLength()];
    b.getByte(expected);
    byte[] actual = kex.encodeInt(secret);
    try {
      assertArrayEquals(expected, actual);
    } catch (Throwable t) {
      System.out.println("  secret = " + secret);
      System.out.println("expected = " + Arrays.toString(expected));
      System.out.println("  actual = " + Arrays.toString(actual));
      throw t;
    }
  }

  private void doEncodeAsMPInt(byte[] secret) {
    Buffer b = new Buffer();
    b.putMPInt(secret);
    byte[] expected = new byte[b.getLength()];
    b.getByte(expected);
    byte[] actual = kex.encodeAsMPInt(Arrays.copyOf(secret, secret.length), true);
    try {
      assertArrayEquals(expected, actual);
    } catch (Throwable t) {
      System.out.println("  secret = " + Arrays.toString(secret));
      System.out.println("expected = " + Arrays.toString(expected));
      System.out.println("  actual = " + Arrays.toString(actual));
      throw t;
    }
  }

  private void doEncodeAsString(byte[] secret) {
    Buffer b = new Buffer();
    b.putString(secret);
    byte[] expected = new byte[b.getLength()];
    b.getByte(expected);
    byte[] actual = kex.encodeAsString(Arrays.copyOf(secret, secret.length), true);
    try {
      assertArrayEquals(expected, actual);
    } catch (Throwable t) {
      System.out.println("  secret = " + Arrays.toString(secret));
      System.out.println("expected = " + Arrays.toString(expected));
      System.out.println("  actual = " + Arrays.toString(actual));
      throw t;
    }
  }

  static class TestKex extends KeyExchange {

    @Override
    public void init(Session session, byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C)
        throws Exception {
      throw new UnsupportedOperationException("Not supported");
    }

    @Override
    public boolean next(Buffer buf) throws Exception {
      throw new UnsupportedOperationException("Not supported");
    }

    @Override
    public int getState() {
      throw new UnsupportedOperationException("Not supported");
    }
  }
}
