package com.jcraft.jsch.android;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.condition.JRE.JAVA_15;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Arrays;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Unit tests for the Java 8 {@link AndroidSignatureEdDSA}, which wraps raw key material in its RFC 8410
 * encodings rather than using the EdEC key specs added in Java 15.
 *
 * <p>
 * These run against {@code target/classes}, where the {@code META-INF/versions} entries are inert,
 * so this is the implementation under test rather than the Java 15 one.
 */
class SignatureEdDSATest {

  private static final byte[] DATA = "data to be signed".getBytes(StandardCharsets.UTF_8);
  private static final byte[] OTHER_DATA = "other data".getBytes(StandardCharsets.UTF_8);

  @ParameterizedTest
  @CsvSource({"Ed25519, 32", "Ed448, 57"})
  @EnabledForJreRange(min = JAVA_15)
  void testSignedByJSchVerifiesWithPlatform(String algo, int keylen) throws Exception {
    KeyPair pair = KeyPairGenerator.getInstance(algo).generateKeyPair();
    byte[] sig = sign(algo, keylen, pair);

    Signature verifier = Signature.getInstance(algo);
    verifier.initVerify(pair.getPublic());
    verifier.update(DATA);
    assertTrue(verifier.verify(sig), algo + " signature should verify with the platform");
  }

  @ParameterizedTest
  @CsvSource({"Ed25519, ssh-ed25519, 32", "Ed448, ssh-ed448, 57"})
  @EnabledForJreRange(min = JAVA_15)
  void testSignedByPlatformVerifiesWithJSch(String algo, String name, int keylen)
      throws Exception {
    KeyPair pair = KeyPairGenerator.getInstance(algo).generateKeyPair();

    Signature signer = Signature.getInstance(algo);
    signer.initSign(pair.getPrivate());
    signer.update(DATA);

    assertTrue(verify(algo, name, keylen, pair, signer.sign(), DATA),
        algo + " platform signature should verify");
  }

  @ParameterizedTest
  @CsvSource({"Ed25519, ssh-ed25519, 32", "Ed448, ssh-ed448, 57"})
  @EnabledForJreRange(min = JAVA_15)
  void testSignatureOverOtherDataFails(String algo, String name, int keylen)
      throws Exception {
    KeyPair pair = KeyPairGenerator.getInstance(algo).generateKeyPair();
    byte[] sig = sign(algo, keylen, pair);

    assertFalse(verify(algo, name, keylen, pair, sig, OTHER_DATA),
        algo + " signature should not verify against other data");
  }

  @ParameterizedTest
  @CsvSource({"Ed25519, 32", "Ed448, 57"})
  @EnabledForJreRange(min = JAVA_15)
  void testShortKeyRejected(String algo, int keylen) throws Exception {
    com.jcraft.jsch.SignatureEdDSA signature = newSignature(algo);
    signature.init();
    byte[] tooShort = new byte[keylen - 1];

    assertThrows(InvalidKeyException.class, () -> signature.setPubKey(tooShort));
    assertThrows(InvalidKeyException.class, () -> signature.setPrvKey(tooShort));
  }

  private static byte[] sign(String algo, int keylen, KeyPair pair) throws Exception {
    com.jcraft.jsch.SignatureEdDSA signer = newSignature(algo);
    signer.init();
    signer.setPrvKey(raw(pair.getPrivate().getEncoded(), keylen));
    signer.update(DATA);
    return signer.sign();
  }

  private static boolean verify(String algo, String name, int keylen, KeyPair pair, byte[] sig,
      byte[] data) throws Exception {
    com.jcraft.jsch.SignatureEdDSA verifier = newSignature(algo);
    verifier.init();
    verifier.setPubKey(raw(pair.getPublic().getEncoded(), keylen));
    verifier.update(data);
    return verifier.verify(sshBlob(name, sig));
  }

  private static com.jcraft.jsch.SignatureEdDSA newSignature(String algo) {
    return algo.equals("Ed25519") ? new SignatureEd25519() : new SignatureEd448();
  }

  // The RFC 8410 encodings end with the raw key, which is what JSch holds.
  private static byte[] raw(byte[] encoded, int keylen) {
    return Arrays.copyOfRange(encoded, encoded.length - keylen, encoded.length);
  }

  // string(name) + string(signature), as it arrives on the wire.
  private static byte[] sshBlob(String name, byte[] sig) throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] part : new byte[][] {name.getBytes(StandardCharsets.UTF_8), sig}) {
      out.write(part.length >>> 24);
      out.write(part.length >>> 16);
      out.write(part.length >>> 8);
      out.write(part.length);
      out.write(part);
    }
    return out.toByteArray();
  }
}
