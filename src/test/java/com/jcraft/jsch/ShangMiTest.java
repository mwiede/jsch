package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jcraft.jsch.bc.ECDHSM2;
import com.jcraft.jsch.bc.ECDHSM2BC;
import com.jcraft.jsch.bc.HMACSM3;
import com.jcraft.jsch.bc.SM3;
import com.jcraft.jsch.bc.SM4CBC;
import com.jcraft.jsch.bc.SM4CTR;
import com.jcraft.jsch.bc.SignatureSM2;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

public class ShangMiTest {

  // SM3 test vector from GM/T 0004-2012
  // Input: "abc" -> 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
  private static final byte[] SM3_INPUT_ABC = "abc".getBytes(StandardCharsets.UTF_8);
  private static final byte[] SM3_EXPECTED_ABC =
      hexToBytes("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");

  // SM4 test vector from GB/T 32907-2016
  // ECB mode: Key=0123456789abcdeffedcba9876543210, PT=0123456789abcdeffedcba9876543210
  // CT=681edf34d206965e86b3e94f536e4246
  // CBC mode with IV=0 gives the same result for the first block (PT XOR IV = PT)
  private static final byte[] SM4_KEY = hexToBytes("0123456789abcdeffedcba9876543210");
  private static final byte[] SM4_IV_ZERO = new byte[16];
  private static final byte[] SM4_PLAINTEXT = hexToBytes("0123456789abcdeffedcba9876543210");
  private static final byte[] SM4_EXPECTED_CBC = hexToBytes("681edf34d206965e86b3e94f536e4246");

  @Test
  public void testSM3KnownVector() throws Exception {
    SM3 sm3 = new SM3();
    sm3.init();
    sm3.update(SM3_INPUT_ABC, 0, SM3_INPUT_ABC.length);
    byte[] digest = sm3.digest();

    assertArrayEquals(SM3_EXPECTED_ABC, digest,
        "SM3(\"abc\") does not match GM/T 0004-2012 vector");
  }

  @Test
  public void testSM3BlockSize() {
    SM3 sm3 = new SM3();
    assertEquals(32, sm3.getBlockSize());
  }

  @Test
  public void testSM4CBCKnownVector() throws Exception {
    SM4CBC cipher = new SM4CBC();
    cipher.init(Cipher.ENCRYPT_MODE, SM4_KEY.clone(), SM4_IV_ZERO.clone());
    byte[] ciphertext = new byte[16];
    cipher.update(SM4_PLAINTEXT.clone(), 0, 16, ciphertext, 0);

    assertArrayEquals(SM4_EXPECTED_CBC, ciphertext,
        "SM4-CBC ciphertext does not match GB/T 32907-2016 vector");
  }

  @Test
  public void testSM4CBCRoundTrip() throws Exception {
    byte[] key = new byte[16];
    byte[] iv = new byte[16];
    new SecureRandom().nextBytes(key);
    new SecureRandom().nextBytes(iv);

    byte[] plaintext = new byte[32];
    new SecureRandom().nextBytes(plaintext);

    SM4CBC enc = new SM4CBC();
    enc.init(Cipher.ENCRYPT_MODE, key, iv);
    byte[] ciphertext = new byte[32];
    enc.update(plaintext, 0, 16, ciphertext, 0);
    enc.update(plaintext, 16, 16, ciphertext, 16);

    SM4CBC dec = new SM4CBC();
    dec.init(Cipher.DECRYPT_MODE, key, iv);
    byte[] decrypted = new byte[32];
    dec.update(ciphertext, 0, 16, decrypted, 0);
    dec.update(ciphertext, 16, 16, decrypted, 16);

    assertArrayEquals(plaintext, decrypted, "SM4-CBC round-trip failed");
  }

  @Test
  public void testSM4CTRRoundTrip() throws Exception {
    byte[] key = new byte[16];
    byte[] iv = new byte[16];
    new SecureRandom().nextBytes(key);
    new SecureRandom().nextBytes(iv);

    byte[] plaintext = new byte[47]; // non-block-aligned to test stream cipher behaviour
    new SecureRandom().nextBytes(plaintext);

    SM4CTR enc = new SM4CTR();
    enc.init(Cipher.ENCRYPT_MODE, key, iv);
    byte[] ciphertext = new byte[47];
    enc.update(plaintext, 0, 47, ciphertext, 0);

    SM4CTR dec = new SM4CTR();
    dec.init(Cipher.DECRYPT_MODE, key, iv);
    byte[] decrypted = new byte[47];
    dec.update(ciphertext, 0, 47, decrypted, 0);

    assertArrayEquals(plaintext, decrypted, "SM4-CTR round-trip failed");
  }

  @Test
  public void testSM4CBCIsCBC() {
    assertTrue(new SM4CBC().isCBC());
  }

  @Test
  public void testSM4CTRIsNotCBC() {
    assertTrue(!new SM4CTR().isCBC());
  }

  @Test
  public void testSM4BlockSize() {
    assertEquals(16, new SM4CBC().getBlockSize());
    assertEquals(16, new SM4CTR().getBlockSize());
  }

  @Test
  public void testSM4IVSize() {
    assertEquals(16, new SM4CBC().getIVSize());
    assertEquals(16, new SM4CTR().getIVSize());
  }

  @Test
  public void testHMACSM3Length() throws Exception {
    HMACSM3 mac = new HMACSM3();
    assertEquals(32, mac.getBlockSize());
    assertEquals("hmac-sm3", mac.getName());
    assertTrue(!mac.isEtM());

    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    mac.init(key);
    mac.update(new byte[] {0x01, 0x02, 0x03}, 0, 3);
    byte[] result = new byte[32];
    mac.doFinal(result, 0);
    // Result should be non-zero
    boolean allZero = true;
    for (byte b : result) {
      if (b != 0) {
        allZero = false;
        break;
      }
    }
    assertTrue(!allZero, "HMAC-SM3 result should not be all-zero");
  }

  @Test
  public void testHMACSM3DifferentKeysDifferentMACs() throws Exception {
    byte[] data = "test data".getBytes(StandardCharsets.UTF_8);

    byte[] key1 = new byte[32];
    byte[] key2 = new byte[32];
    new SecureRandom().nextBytes(key1);
    new SecureRandom().nextBytes(key2);

    HMACSM3 mac1 = new HMACSM3();
    mac1.init(key1);
    mac1.update(data, 0, data.length);
    byte[] result1 = new byte[32];
    mac1.doFinal(result1, 0);

    HMACSM3 mac2 = new HMACSM3();
    mac2.init(key2);
    mac2.update(data, 0, data.length);
    byte[] result2 = new byte[32];
    mac2.doFinal(result2, 0);

    assertNotEquals(java.util.Arrays.toString(result1), java.util.Arrays.toString(result2),
        "Different keys should produce different HMAC-SM3 values");
  }

  @Test
  public void testSM2SignVerifyRoundTrip() throws Exception {
    // Generate a random EC key pair on the SM2 curve using BouncyCastle
    org.bouncycastle.asn1.gm.GMNamedCurves.getByName("sm2p256v1"); // ensure accessible
    org.bouncycastle.asn1.x9.X9ECParameters x9 =
        org.bouncycastle.asn1.gm.GMNamedCurves.getByName("sm2p256v1");
    org.bouncycastle.crypto.params.ECDomainParameters domainParams =
        new org.bouncycastle.crypto.params.ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(),
            x9.getH());

    org.bouncycastle.crypto.generators.ECKeyPairGenerator gen =
        new org.bouncycastle.crypto.generators.ECKeyPairGenerator();
    gen.init(new org.bouncycastle.crypto.params.ECKeyGenerationParameters(domainParams,
        new SecureRandom()));
    org.bouncycastle.crypto.AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

    org.bouncycastle.crypto.params.ECPrivateKeyParameters prvKey =
        (org.bouncycastle.crypto.params.ECPrivateKeyParameters) keyPair.getPrivate();
    org.bouncycastle.crypto.params.ECPublicKeyParameters pubKey =
        (org.bouncycastle.crypto.params.ECPublicKeyParameters) keyPair.getPublic();

    byte[] prvBytes = prvKey.getD().toByteArray();
    // Ensure 32 bytes (remove leading zero byte if present from BigInteger encoding)
    if (prvBytes.length == 33 && prvBytes[0] == 0) {
      byte[] tmp = new byte[32];
      System.arraycopy(prvBytes, 1, tmp, 0, 32);
      prvBytes = tmp;
    }
    byte[] pubBytes = pubKey.getQ().getEncoded(false); // uncompressed: 0x04 || x || y (65 bytes)

    byte[] message = "test message for SM2 signature".getBytes(StandardCharsets.UTF_8);

    // Sign
    SignatureSM2 signer = new SignatureSM2();
    signer.init();
    signer.setPrvKey(prvBytes);
    signer.update(message);
    byte[] sig = signer.sign();

    // Verify
    SignatureSM2 verifier = new SignatureSM2();
    verifier.init();
    verifier.setPubKey(pubBytes);
    verifier.update(message);
    assertTrue(verifier.verify(sig), "SM2 sign/verify round-trip failed");
  }

  @Test
  public void testSM2VerifyWithSSHEnvelope() throws Exception {
    // Test verify() with SSH signature envelope format (as used in SSH protocol)
    org.bouncycastle.asn1.x9.X9ECParameters x9 =
        org.bouncycastle.asn1.gm.GMNamedCurves.getByName("sm2p256v1");
    org.bouncycastle.crypto.params.ECDomainParameters domainParams =
        new org.bouncycastle.crypto.params.ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(),
            x9.getH());

    org.bouncycastle.crypto.generators.ECKeyPairGenerator gen =
        new org.bouncycastle.crypto.generators.ECKeyPairGenerator();
    gen.init(new org.bouncycastle.crypto.params.ECKeyGenerationParameters(domainParams,
        new SecureRandom()));
    org.bouncycastle.crypto.AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

    org.bouncycastle.crypto.params.ECPrivateKeyParameters prvKey =
        (org.bouncycastle.crypto.params.ECPrivateKeyParameters) keyPair.getPrivate();
    org.bouncycastle.crypto.params.ECPublicKeyParameters pubKey =
        (org.bouncycastle.crypto.params.ECPublicKeyParameters) keyPair.getPublic();

    byte[] prvBytes = prvKey.getD().toByteArray();
    if (prvBytes.length == 33 && prvBytes[0] == 0) {
      byte[] tmp = new byte[32];
      System.arraycopy(prvBytes, 1, tmp, 0, 32);
      prvBytes = tmp;
    }
    byte[] pubBytes = pubKey.getQ().getEncoded(false);

    byte[] message = "test message for SSH envelope".getBytes(StandardCharsets.UTF_8);

    // Sign (raw DER blob)
    SignatureSM2 signer = new SignatureSM2();
    signer.init();
    signer.setPrvKey(prvBytes);
    signer.update(message);
    byte[] rawSig = signer.sign();

    // Wrap in SSH signature envelope: string("sm2") + string(rawSig)
    Buffer buf = new Buffer();
    buf.putString("sm2".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    buf.putString(rawSig);
    byte[] sshSig = java.util.Arrays.copyOf(buf.buffer, buf.index);

    // Verify with envelope
    SignatureSM2 verifier = new SignatureSM2();
    verifier.init();
    verifier.setPubKey(pubBytes);
    verifier.update(message);
    assertTrue(verifier.verify(sshSig), "SM2 verify with SSH envelope failed");
  }

  /**
   * Verifies that BC's SM2KeyExchange with kLen=256 (bits) produces the same shared secret as the
   * manual ECDHSM2 implementation. This confirms that the original failure was caused solely by
   * passing kLen=32 (bits = 4 bytes) instead of kLen=256 (bits = 32 bytes).
   */
  @Test
  public void testECDHSM2ManualMatchesBC() throws Exception {
    // Generate a fixed client key pair
    org.bouncycastle.asn1.x9.X9ECParameters x9 =
        org.bouncycastle.asn1.gm.GMNamedCurves.getByName("sm2p256v1");
    org.bouncycastle.crypto.params.ECDomainParameters domain =
        new org.bouncycastle.crypto.params.ECDomainParameters(
            x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());

    org.bouncycastle.crypto.generators.ECKeyPairGenerator gen =
        new org.bouncycastle.crypto.generators.ECKeyPairGenerator();

    // Client key pair (used by both ECDHSM2 and ECDHSM2BC)
    gen.init(new org.bouncycastle.crypto.params.ECKeyGenerationParameters(
        domain, new SecureRandom()));
    org.bouncycastle.crypto.AsymmetricCipherKeyPair clientKP = gen.generateKeyPair();
    org.bouncycastle.crypto.params.ECPrivateKeyParameters clientPriv =
        (org.bouncycastle.crypto.params.ECPrivateKeyParameters) clientKP.getPrivate();

    // Server key pair (peer public key)
    org.bouncycastle.crypto.AsymmetricCipherKeyPair serverKP = gen.generateKeyPair();
    org.bouncycastle.crypto.params.ECPublicKeyParameters serverPub =
        (org.bouncycastle.crypto.params.ECPublicKeyParameters) serverKP.getPublic();

    // Encode server's public key as uncompressed point and split into (x, y)
    byte[] serverQ = serverPub.getQ().getEncoded(false); // 04 || x || y
    byte[] peerX = new byte[32];
    byte[] peerY = new byte[32];
    System.arraycopy(serverQ, 1, peerX, 0, 32);
    System.arraycopy(serverQ, 33, peerY, 0, 32);

    // Manual implementation
    ECDHSM2 manual = new ECDHSM2();
    injectPrivateKey(manual, clientPriv, serverQ);
    byte[] manualSecret = manual.getSecret(peerX, peerY);

    // BC-based implementation
    ECDHSM2BC bc = new ECDHSM2BC();
    injectPrivateKey(bc, clientPriv, serverQ);
    byte[] bcSecret = bc.getSecret(peerX, peerY);

    assertArrayEquals(manualSecret, bcSecret,
        "Manual ECDHSM2 and BC-based ECDHSM2BC must produce identical shared secrets");
  }

  /** Injects a pre-generated private key into an ECDHSM2 or ECDHSM2BC instance via reflection. */
  private static void injectPrivateKey(Object ecdh,
      org.bouncycastle.crypto.params.ECPrivateKeyParameters priv,
      byte[] publicPoint) throws Exception {
    java.lang.reflect.Field privField = ecdh.getClass().getDeclaredField("privateKey");
    privField.setAccessible(true);
    privField.set(ecdh, priv);

    java.lang.reflect.Field qField = ecdh.getClass().getDeclaredField("Q_array");
    qField.setAccessible(true);
    qField.set(ecdh, publicPoint);
  }

  private static byte[] hexToBytes(String hex) {
    int len = hex.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
          + Character.digit(hex.charAt(i + 1), 16));
    }
    return data;
  }
}
