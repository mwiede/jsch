package com.jcraft.jsch;

import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class KeyPair2Test {

  @TempDir
  public Path tmpDir;

  static Stream<Arguments> keyArgs() {
    return Stream.of(
        // PuTTY v2 keys
        Arguments.of("ppkv2_ed448_unix.ppk", null, "ssh-ed448"),
        Arguments.of("ppkv2_ed448_unix_encrypted.ppk", "secret123", "ssh-ed448"),
        Arguments.of("ppkv2_ed448_windows.ppk", null, "ssh-ed448"),
        Arguments.of("ppkv2_ed448_windows_encrypted.ppk", "secret123", "ssh-ed448"),
        // PuTTY v3 keys
        Arguments.of("ppkv3_ed448_unix.ppk", null, "ssh-ed448"),
        Arguments.of("ppkv3_ed448_unix_encrypted.ppk", "secret123", "ssh-ed448"),
        Arguments.of("ppkv3_ed448_windows.ppk", null, "ssh-ed448"),
        Arguments.of("ppkv3_ed448_windows_encrypted.ppk", "secret123", "ssh-ed448"),
        // PKCS8 keys
        Arguments.of("pkcs8_ed448", null, "ssh-ed448"),
        Arguments.of("pkcs8_ed448_encrypted_scrypt", "secret123", "ssh-ed448"));
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
}
