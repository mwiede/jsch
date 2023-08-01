package com.jcraft.jsch;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

class KeyPairTest {

  @TempDir
  public Path tmpDir;

  static Stream<Arguments> keyArgs() {
    return Stream.of(
        // docker/id_rsa rsa
        Arguments.of("docker/id_rsa", null, "ssh-rsa"),
        // docker/ssh_host_rsa_key openssh format
        Arguments.of("docker/ssh_host_rsa_key", null, "ssh-rsa"),
        // encrypted_openssh_private_key_rsa
        Arguments.of("encrypted_openssh_private_key_rsa", "secret123", "ssh-rsa"),
        // docker/id_dsa
        Arguments.of("docker/id_dsa", null, "ssh-dss"),
        // dsa openssh format
        Arguments.of("docker/ssh_host_dsa_key", null, "ssh-dss"),
        // encrypted dsa
        Arguments.of("encrypted_openssh_private_key_dsa", "secret123", "ssh-dss"),
        // unencrypted RSA with windows (\r\n) line endings
        Arguments.of("issue362_rsa", null, "ssh-rsa"),
        Arguments.of("issue_369_rsa_opensshv1", null, "ssh-rsa"),
        Arguments.of("issue_369_rsa_pem", null, "ssh-rsa"),
        Arguments.of("encrypted_issue_369_rsa_opensshv1", "secret123", "ssh-rsa"),
        Arguments.of("encrypted_issue_369_rsa_pem", "secret123", "ssh-rsa"),
        // ecdsa EC private key format
        Arguments.of("docker/id_ecdsa256", null, "ecdsa-sha2-nistp256"), //
        Arguments.of("docker/id_ecdsa384", null, "ecdsa-sha2-nistp384"), //
        Arguments.of("docker/id_ecdsa521", null, "ecdsa-sha2-nistp521"),
        Arguments.of("docker/ssh_host_ecdsa256_key", null, "ecdsa-sha2-nistp256"),
        Arguments.of("docker/ssh_host_ecdsa384_key", null, "ecdsa-sha2-nistp384"),
        Arguments.of("docker/ssh_host_ecdsa521_key", null, "ecdsa-sha2-nistp521"),
        // encrypted ecdsa
        Arguments.of("encrypted_openssh_private_key_ecdsa", "secret123", "ecdsa-sha2-nistp256"),
        // PuTTY v2 keys
        Arguments.of("ppkv2_dsa_unix.ppk", null, "ssh-dss"),
        Arguments.of("ppkv2_dsa_unix_encrypted.ppk", "secret123", "ssh-dss"),
        Arguments.of("ppkv2_dsa_windows.ppk", null, "ssh-dss"),
        Arguments.of("ppkv2_dsa_windows_encrypted.ppk", "secret123", "ssh-dss"),
        Arguments.of("ppkv2_rsa_unix.ppk", null, "ssh-rsa"),
        Arguments.of("ppkv2_rsa_unix_encrypted.ppk", "secret123", "ssh-rsa"),
        Arguments.of("ppkv2_rsa_windows.ppk", null, "ssh-rsa"),
        Arguments.of("ppkv2_rsa_windows_encrypted.ppk", "secret123", "ssh-rsa"),
        Arguments.of("ppkv2_ecdsa256_unix.ppk", null, "ecdsa-sha2-nistp256"),
        Arguments.of("ppkv2_ecdsa256_unix_encrypted.ppk", "secret123", "ecdsa-sha2-nistp256"),
        Arguments.of("ppkv2_ecdsa384_unix.ppk", null, "ecdsa-sha2-nistp384"),
        Arguments.of("ppkv2_ecdsa384_unix_encrypted.ppk", "secret123", "ecdsa-sha2-nistp384"),
        Arguments.of("ppkv2_ecdsa521_unix.ppk", null, "ecdsa-sha2-nistp521"),
        Arguments.of("ppkv2_ecdsa521_unix_encrypted.ppk", "secret123", "ecdsa-sha2-nistp521"),
        Arguments.of("ppkv2_ecdsa256_windows.ppk", null, "ecdsa-sha2-nistp256"),
        Arguments.of("ppkv2_ecdsa256_windows_encrypted.ppk", "secret123", "ecdsa-sha2-nistp256"),
        Arguments.of("ppkv2_ecdsa384_windows.ppk", null, "ecdsa-sha2-nistp384"),
        Arguments.of("ppkv2_ecdsa384_windows_encrypted.ppk", "secret123", "ecdsa-sha2-nistp384"),
        Arguments.of("ppkv2_ecdsa521_windows.ppk", null, "ecdsa-sha2-nistp521"),
        Arguments.of("ppkv2_ecdsa521_windows_encrypted.ppk", "secret123", "ecdsa-sha2-nistp521"),
        Arguments.of("ppkv2_ed25519_unix.ppk", null, "ssh-ed25519"),
        Arguments.of("ppkv2_ed25519_unix_encrypted.ppk", "secret123", "ssh-ed25519"),
        Arguments.of("ppkv2_ed25519_windows.ppk", null, "ssh-ed25519"),
        Arguments.of("ppkv2_ed25519_windows_encrypted.ppk", "secret123", "ssh-ed25519"),
        // PuTTY v3 keys
        Arguments.of("ppkv3_dsa_unix.ppk", null, "ssh-dss"),
        Arguments.of("ppkv3_dsa_unix_encrypted.ppk", "secret123", "ssh-dss"),
        Arguments.of("ppkv3_dsa_windows.ppk", null, "ssh-dss"),
        Arguments.of("ppkv3_dsa_windows_encrypted.ppk", "secret123", "ssh-dss"),
        Arguments.of("ppkv3_rsa_unix.ppk", null, "ssh-rsa"),
        Arguments.of("ppkv3_rsa_unix_encrypted.ppk", "secret123", "ssh-rsa"),
        Arguments.of("ppkv3_rsa_windows.ppk", null, "ssh-rsa"),
        Arguments.of("ppkv3_rsa_windows_encrypted.ppk", "secret123", "ssh-rsa"),
        Arguments.of("ppkv3_ecdsa256_unix.ppk", null, "ecdsa-sha2-nistp256"),
        Arguments.of("ppkv3_ecdsa256_unix_encrypted.ppk", "secret123", "ecdsa-sha2-nistp256"),
        Arguments.of("ppkv3_ecdsa384_unix.ppk", null, "ecdsa-sha2-nistp384"),
        Arguments.of("ppkv3_ecdsa384_unix_encrypted.ppk", "secret123", "ecdsa-sha2-nistp384"),
        Arguments.of("ppkv3_ecdsa521_unix.ppk", null, "ecdsa-sha2-nistp521"),
        Arguments.of("ppkv3_ecdsa521_unix_encrypted.ppk", "secret123", "ecdsa-sha2-nistp521"),
        Arguments.of("ppkv3_ecdsa256_windows.ppk", null, "ecdsa-sha2-nistp256"),
        Arguments.of("ppkv3_ecdsa256_windows_encrypted.ppk", "secret123", "ecdsa-sha2-nistp256"),
        Arguments.of("ppkv3_ecdsa384_windows.ppk", null, "ecdsa-sha2-nistp384"),
        Arguments.of("ppkv3_ecdsa384_windows_encrypted.ppk", "secret123", "ecdsa-sha2-nistp384"),
        Arguments.of("ppkv3_ecdsa521_windows.ppk", null, "ecdsa-sha2-nistp521"),
        Arguments.of("ppkv3_ecdsa521_windows_encrypted.ppk", "secret123", "ecdsa-sha2-nistp521"),
        Arguments.of("ppkv3_ed25519_unix.ppk", null, "ssh-ed25519"),
        Arguments.of("ppkv3_ed25519_unix_encrypted.ppk", "secret123", "ssh-ed25519"),
        Arguments.of("ppkv3_ed25519_windows.ppk", null, "ssh-ed25519"),
        Arguments.of("ppkv3_ed25519_windows_encrypted.ppk", "secret123", "ssh-ed25519"),
        // PKCS8 keys
        Arguments.of("pkcs8_dsa", null, "ssh-dss"),
        Arguments.of("pkcs8_dsa_encrypted_hmacsha1", "secret123", "ssh-dss"),
        Arguments.of("pkcs8_dsa_encrypted_hmacsha256", "secret123", "ssh-dss"),
        Arguments.of("pkcs8_rsa", null, "ssh-rsa"),
        Arguments.of("pkcs8_rsa_encrypted_hmacsha1", "secret123", "ssh-rsa"),
        Arguments.of("pkcs8_rsa_encrypted_hmacsha256", "secret123", "ssh-rsa"),
        Arguments.of("pkcs8_ecdsa256", null, "ecdsa-sha2-nistp256"),
        Arguments.of("pkcs8_ecdsa256_encrypted_scrypt", "secret123", "ecdsa-sha2-nistp256"),
        Arguments.of("pkcs8_ecdsa384", null, "ecdsa-sha2-nistp384"),
        Arguments.of("pkcs8_ecdsa384_encrypted_scrypt", "secret123", "ecdsa-sha2-nistp384"),
        Arguments.of("pkcs8_ecdsa521", null, "ecdsa-sha2-nistp521"),
        Arguments.of("pkcs8_ecdsa521_encrypted_scrypt", "secret123", "ecdsa-sha2-nistp521"),
        Arguments.of("pkcs8_ed25519", null, "ssh-ed25519"),
        Arguments.of("pkcs8_ed25519_encrypted_scrypt", "secret123", "ssh-ed25519"));
  }

  @ParameterizedTest
  @MethodSource("keyArgs")
  void loadKey(String path, String password, String keyType)
      throws URISyntaxException, JSchException {
    final JSch jSch = new JSch();
    final String prvkey =
        Paths.get(ClassLoader.getSystemResource(path).toURI()).toFile().getAbsolutePath();
    assertTrue(new File(prvkey).exists());
    assertDoesNotThrow(() -> {
      if (null != password) {
        jSch.addIdentity(prvkey, password);
      } else {
        jSch.addIdentity(prvkey);
      }
    });
    assertEquals(keyType, jSch.getIdentityRepository().getIdentities().get(0).getAlgName());
  }

  @Test
  void genKeypair() {
    final JSch jSch = new JSch();
    assertDoesNotThrow(() -> {
      KeyPair kpair = KeyPair.genKeyPair(jSch, KeyPair.RSA, 1024);
      kpair.writePrivateKey(tmpDir.resolve("my-private-key").toString());
    });
  }

  @Test
  void genKeypairEncrypted() {
    final JSch jSch = new JSch();
    assertDoesNotThrow(() -> {
      KeyPair kpair = KeyPair.genKeyPair(jSch, KeyPair.RSA, 1024);
      kpair.writePrivateKey(tmpDir.resolve("my-private-key-encrypted").toString(),
          "my-password".getBytes(UTF_8));
    });
  }

  @ParameterizedTest
  @ValueSource(strings = {"encrypted_openssh_private_key_rsa", "encrypted_openssh_private_key_dsa",
      "encrypted_openssh_private_key_ecdsa"})
  void decryptEncryptedOpensshKey(String keyFile) throws URISyntaxException, JSchException {
    final JSch jSch = new JSch();
    final String prvkey =
        Paths.get(ClassLoader.getSystemResource(keyFile).toURI()).toFile().getAbsolutePath();
    assertTrue(new File(prvkey).exists());
    IdentityFile identity = IdentityFile.newInstance(prvkey, null, jSch.instLogger);

    // Decrypt the key file
    assertTrue(identity.getKeyPair().decrypt("secret123"));

    // From now on, the pair now longer counts as encrypted
    assertFalse(identity.getKeyPair().isEncrypted());
    assertNotNull(identity.getKeyPair().getPrivateKey());
    // An unencrypted key pair should allow #decrypt(null)
    // com.jcraft.jsch.UserAuthPublicKey relies on this
    assertTrue(identity.getKeyPair().decrypt((byte[]) null));
    assertTrue(identity.getKeyPair().decrypt((String) null));
  }

}
