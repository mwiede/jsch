package com.jcraft.jsch;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import com.jcraft.jsch.android.AndroidJSch;
import com.jcraft.jsch.android.SignatureEd25519;
import com.jcraft.jsch.android.SignatureEd448;
import com.jcraft.jsch.android.AndroidXDH;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class EdDSAAndroidTest {

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

  // RFC 8032 section 7.1, test 1.
  private static final byte[] PRIVATE_KEY =
      fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  private static final byte[] PUBLIC_KEY =
      fromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  private static final byte[] EXPECTED_SIGNATURE =
      fromHex(
          "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
              + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

  @Test
  public void keepsTheBaseConfigurationUntilEnabled() {
    assertEquals("Dalvik", System.getProperty("java.vm.name"));
    assertEquals("com.jcraft.jsch.bc.SignatureEd25519", JSch.getConfig("ssh-ed25519"));
    assertEquals("com.jcraft.jsch.bc.SignatureEd448", JSch.getConfig("ssh-ed448"));
    assertEquals("com.jcraft.jsch.bc.XDH", JSch.getConfig("xdh"));
    assertEquals("com.jcraft.jsch.bc.KeyPairGenEdDSA", JSch.getConfig("keypairgen.eddsa"));
  }

  @Test
  public void signsAndVerifiesWithAndroidJca() throws Exception {
    assumeTrue("No stock provider for imported Ed25519 keys", isSupported("Ed25519"));
    AndroidJSch.configure();
    assertEquals(SignatureEd25519.class.getName(), JSch.getConfig("ssh-ed25519"));
    assertSignsAndVerifies();
  }

  @Test
  public void signsAndVerifiesWithAnInstalledProvider() throws Exception {
    Provider original = Security.getProvider("BC");
    int originalPosition = providerPosition("BC");
    if (original != null) {
      Security.removeProvider("BC");
    }
    assertEquals(1, Security.insertProviderAt(new BouncyCastleProvider(), 1));
    try {
      assertTrue(isSupported("Ed25519"));
      AndroidJSch.configure();
      assertEquals(SignatureEd25519.class.getName(), JSch.getConfig("ssh-ed25519"));
      assertSignsAndVerifies();
    } finally {
      Security.removeProvider("BC");
      if (original != null) {
        Security.insertProviderAt(original, originalPosition);
      }
    }
  }

  @Test
  public void x25519UsesAndroidProviderWhenAvailable() throws Exception {
    assumeTrue("No stock X25519 provider", isX25519Supported());
    AndroidJSch.configure();
    assertEquals(AndroidXDH.class.getName(), JSch.getConfig("xdh"));
    AndroidXDH first = new AndroidXDH();
    AndroidXDH second = new AndroidXDH();
    first.init("X25519", 32);
    second.init("X25519", 32);
    assertArrayEquals(first.getSecret(second.getQ()), second.getSecret(first.getQ()));
  }

  @Test
  public void x448KeepsBouncyCastleFallback() throws Exception {
    AndroidXDH first = new AndroidXDH();
    AndroidXDH second = new AndroidXDH();
    first.init("X448", 56);
    second.init("X448", 56);
    assertArrayEquals(first.getSecret(second.getQ()), second.getSecret(first.getQ()));
  }

  private static boolean isX25519Supported() {
    for (Provider provider : Security.getProviders()) {
      if (provider.getService("KeyAgreement", "X25519") != null
          && provider.getService("KeyPairGenerator", "X25519") != null
          && provider.getService("KeyFactory", "X25519") != null) {
        return true;
      }
    }
    return false;
  }

  private static void assertSignsAndVerifies() throws Exception {
    com.jcraft.jsch.SignatureEdDSA signer = new SignatureEd25519();
    signer.init();
    signer.setPrvKey(PRIVATE_KEY);
    signer.update(new byte[0]);
    byte[] signature = signer.sign();
    assertArrayEquals(EXPECTED_SIGNATURE, signature);

    com.jcraft.jsch.SignatureEdDSA verifier = new SignatureEd25519();
    verifier.init();
    verifier.setPubKey(PUBLIC_KEY);
    verifier.update(new byte[0]);
    assertTrue(verifier.verify(sshSignature(signature)));
  }

  private static int providerPosition(String name) {
    Provider[] providers = Security.getProviders();
    for (int i = 0; i < providers.length; i++) {
      if (providers[i].getName().equals(name)) {
        return i + 1;
      }
    }
    return -1;
  }

  // Older releases have no EdDSA at all, and Ed448 is missing everywhere so far. Those have to
  // fail in init(), which is what leaves the algorithm out of the ones offered to the server.
  @Test
  public void unsupportedCurvesFailInInit() throws Exception {
    assertUnsupported(new SignatureEd25519(), "Ed25519");
    assertUnsupported(new SignatureEd448(), "Ed448");
  }

  private static void assertUnsupported(com.jcraft.jsch.SignatureEdDSA signature, String algo)
      throws Exception {
    if (isSupported(algo)) {
      return;
    }
    try {
      signature.init();
      fail(algo + " has no provider, so init() should have failed");
    } catch (NoSuchAlgorithmException expected) {
      // the availability check drops the algorithm
    }
  }

  // Both services have to come from one provider: the key store provider registers an Ed25519
  // KeyFactory that rejects raw key material, and its Signature rejects imported keys.
  private static boolean isSupported(String algo) {
    for (Provider provider : Security.getProviders()) {
      if (provider.getService("Signature", algo) != null
          && provider.getService("KeyFactory", algo) != null) {
        return true;
      }
    }
    return false;
  }

  private static byte[] sshSignature(byte[] signature) {
    byte[] name = "ssh-ed25519".getBytes(StandardCharsets.UTF_8);
    byte[] result = new byte[8 + name.length + signature.length];
    writeLength(result, 0, name.length);
    System.arraycopy(name, 0, result, 4, name.length);
    writeLength(result, 4 + name.length, signature.length);
    System.arraycopy(signature, 0, result, 8 + name.length, signature.length);
    return result;
  }

  private static void writeLength(byte[] target, int offset, int length) {
    target[offset] = (byte) (length >>> 24);
    target[offset + 1] = (byte) (length >>> 16);
    target[offset + 2] = (byte) (length >>> 8);
    target[offset + 3] = (byte) length;
  }

  private static byte[] fromHex(String hex) {
    byte[] result = new byte[hex.length() / 2];
    for (int i = 0; i < result.length; i++) {
      result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return result;
  }
}
