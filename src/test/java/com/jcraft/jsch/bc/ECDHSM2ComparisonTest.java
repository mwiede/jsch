package com.jcraft.jsch.bc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.security.SecureRandom;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.junit.jupiter.api.Test;

public class ECDHSM2ComparisonTest {

  /**
   * Verifies that BC's SM2KeyExchange with kLen=256 (bits) produces the same shared secret as the
   * manual ECDHSM2 implementation. This confirms that the original failure was caused solely by
   * passing kLen=32 (bits = 4 bytes) instead of kLen=256 (bits = 32 bytes).
   */
  @Test
  public void testECDHSM2ManualMatchesBC() throws Exception {
    X9ECParameters x9 = GMNamedCurves.getByName("sm2p256v1");
    ECDomainParameters domain =
        new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());

    ECKeyPairGenerator gen = new ECKeyPairGenerator();
    gen.init(new ECKeyGenerationParameters(domain, new SecureRandom()));

    // Client key pair (used by both ECDHSM2 and ECDHSM2BC)
    AsymmetricCipherKeyPair clientKP = gen.generateKeyPair();
    ECPrivateKeyParameters clientPriv = (ECPrivateKeyParameters) clientKP.getPrivate();

    // Server key pair (peer public key)
    AsymmetricCipherKeyPair serverKP = gen.generateKeyPair();
    ECPublicKeyParameters serverPub = (ECPublicKeyParameters) serverKP.getPublic();

    // Encode server's public key as uncompressed point and split into (x, y)
    byte[] serverQ = serverPub.getQ().getEncoded(false); // 04 || x || y
    byte[] peerX = new byte[32];
    byte[] peerY = new byte[32];
    System.arraycopy(serverQ, 1, peerX, 0, 32);
    System.arraycopy(serverQ, 33, peerY, 0, 32);

    // Manual implementation
    ECDHSM2 manual = new ECDHSM2();
    manual.initForTest(clientPriv, serverQ);
    byte[] manualSecret = manual.getSecret(peerX, peerY);

    // BC-based implementation
    ECDHSM2BC bc = new ECDHSM2BC();
    bc.initForTest(clientPriv, serverQ);
    byte[] bcSecret = bc.getSecret(peerX, peerY);

    assertArrayEquals(manualSecret, bcSecret,
        "Manual ECDHSM2 and BC-based ECDHSM2BC must produce identical shared secrets");
  }
}
