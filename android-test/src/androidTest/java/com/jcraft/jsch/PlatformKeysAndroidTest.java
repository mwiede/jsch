package com.jcraft.jsch;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import com.jcraft.jsch.android.AndroidJSch;
import com.jcraft.jsch.android.SignatureEd25519;
import com.jcraft.jsch.android.SignatureEd448;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Checks JSch's EdDSA classes against keys and signatures made by the platform's own providers.
 */
public class PlatformKeysAndroidTest {

  private static final byte[] DATA = "data to be signed".getBytes(StandardCharsets.UTF_8);
  private static final byte[] OTHER_DATA = "other data".getBytes(StandardCharsets.UTF_8);

  private String originalEd25519;
  private String originalEd448;
  private String originalXdh;

  @Before
  public void saveConfiguration() {
    originalEd25519 = JSch.getConfig("ssh-ed25519");
    originalEd448 = JSch.getConfig("ssh-ed448");
    originalXdh = JSch.getConfig("xdh");
  }

  @After
  public void restoreConfiguration() {
    JSch.setConfig("ssh-ed25519", originalEd25519);
    JSch.setConfig("ssh-ed448", originalEd448);
    JSch.setConfig("xdh", originalXdh);
  }

  @Test
  public void signedByJSchVerifiesWithPlatform() throws Exception {
    for (Curve curve : curves()) {
      KeyPair pair = KeyPairGenerator.getInstance(curve.algo).generateKeyPair();
      byte[] sig = sign(curve, pair);

      Signature verifier = Signature.getInstance(curve.algo);
      verifier.initVerify(pair.getPublic());
      verifier.update(DATA);
      assertTrue(curve.algo + " signature should verify with the platform", verifier.verify(sig));
    }
  }

  @Test
  public void signedByPlatformVerifiesWithJSch() throws Exception {
    for (Curve curve : curves()) {
      KeyPair pair = KeyPairGenerator.getInstance(curve.algo).generateKeyPair();

      Signature signer = Signature.getInstance(curve.algo);
      signer.initSign(pair.getPrivate());
      signer.update(DATA);

      assertTrue(curve.algo + " platform signature should verify",
          verify(curve, pair, signer.sign(), DATA));
    }
  }

  @Test
  public void signatureOverOtherDataFails() throws Exception {
    for (Curve curve : curves()) {
      KeyPair pair = KeyPairGenerator.getInstance(curve.algo).generateKeyPair();
      byte[] sig = sign(curve, pair);

      assertFalse(curve.algo + " signature should not verify against other data",
          verify(curve, pair, sig, OTHER_DATA));
    }
  }

  @Test
  public void shortKeyRejected() throws Exception {
    for (Curve curve : curves()) {
      com.jcraft.jsch.SignatureEdDSA signature = curve.newSignature();
      signature.init();
      byte[] tooShort = new byte[curve.keyLength - 1];
      try {
        signature.setPubKey(tooShort);
        fail("short public key accepted");
      } catch (InvalidKeyException expected) {
        // expected
      }
      try {
        signature.setPrvKey(tooShort);
        fail("short private key accepted");
      } catch (InvalidKeyException expected) {
        // expected
      }
    }
  }

  @Test
  public void rejectedImportedKeysKeepTheFallback() throws Exception {
    assumeTrue("No Ed25519 signing provider", isSupported("Ed25519"));
    Provider signingProvider = Security.getProviders("Signature.Ed25519")[0];
    Provider rejecting = new RejectingProvider(signingProvider);
    rejecting.put("KeyFactory.Ed25519", RejectedKeys.class.getName());
    RejectedKeys.attempts = 0;
    JSch.setConfig("ssh-ed25519", "com.jcraft.jsch.bc.SignatureEd25519");
    assertEquals(1, Security.insertProviderAt(rejecting, 1));
    try {
      AndroidJSch.configure();
      assertEquals(1, RejectedKeys.attempts);
      assertEquals("com.jcraft.jsch.bc.SignatureEd25519", JSch.getConfig("ssh-ed25519"));
    } finally {
      Security.removeProvider(rejecting.getName());
    }
  }

  private static final class Curve {
    final String algo;
    final String name;
    final int keyLength;

    Curve(String algo, String name, int keyLength) {
      this.algo = algo;
      this.name = name;
      this.keyLength = keyLength;
    }

    com.jcraft.jsch.SignatureEdDSA newSignature() {
      return algo.equals("Ed25519") ? new SignatureEd25519() : new SignatureEd448();
    }
  }

  // Ed448 is only included where the platform has it.
  private static Curve[] curves() {
    Curve ed25519 = new Curve("Ed25519", "ssh-ed25519", 32);
    Curve ed448 = new Curve("Ed448", "ssh-ed448", 57);
    assumeTrue("No stock provider for imported Ed25519 keys", isSupported("Ed25519"));
    return isSupported("Ed448") ? new Curve[] {ed25519, ed448} : new Curve[] {ed25519};
  }

  private static boolean isSupported(String algo) {
    for (Provider provider : Security.getProviders()) {
      if (provider.getService("Signature", algo) != null
          && provider.getService("KeyFactory", algo) != null
          && provider.getService("KeyPairGenerator", algo) != null) {
        return true;
      }
    }
    return false;
  }

  private static byte[] sign(Curve curve, KeyPair pair) throws Exception {
    com.jcraft.jsch.SignatureEdDSA signer = curve.newSignature();
    signer.init();
    signer.setPrvKey(raw(pair.getPrivate().getEncoded(), curve.keyLength));
    signer.update(DATA);
    return signer.sign();
  }

  private static boolean verify(Curve curve, KeyPair pair, byte[] sig, byte[] data)
      throws Exception {
    com.jcraft.jsch.SignatureEdDSA verifier = curve.newSignature();
    verifier.init();
    verifier.setPubKey(raw(pair.getPublic().getEncoded(), curve.keyLength));
    verifier.update(data);
    return verifier.verify(sshBlob(curve.name, sig));
  }

  // The RFC 8410 encodings end with the raw key, which is what JSch holds.
  private static byte[] raw(byte[] encoded, int keyLength) {
    return Arrays.copyOfRange(encoded, encoded.length - keyLength, encoded.length);
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

  public static final class RejectedKeys extends KeyFactorySpi {
    static int attempts;

    @Override
    protected PublicKey engineGeneratePublic(KeySpec key) throws InvalidKeySpecException {
      throw new InvalidKeySpecException("Imported keys are not supported");
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec key) throws InvalidKeySpecException {
      attempts++;
      throw new InvalidKeySpecException("Imported keys are not supported");
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> type)
        throws InvalidKeySpecException {
      throw new InvalidKeySpecException("Imported keys are not supported");
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
      throw new InvalidKeyException("Imported keys are not supported");
    }
  }

  private static final class RejectingProvider extends Provider {
    private static final long serialVersionUID = 1L;
    private final transient Provider signingProvider;

    RejectingProvider(Provider signingProvider) {
      super("RejectedImportedKeys", 1.0, "Test provider");
      this.signingProvider = signingProvider;
    }

    @Override
    public Service getService(String type, String algorithm) {
      if ("Signature".equals(type) && "Ed25519".equals(algorithm)) {
        return new Service(this, type, algorithm, "Ed25519", null, null) {
          @Override
          public Object newInstance(Object parameter) throws NoSuchAlgorithmException {
            return Signature.getInstance("Ed25519", signingProvider);
          }
        };
      }
      return super.getService(type, algorithm);
    }
  }
}
