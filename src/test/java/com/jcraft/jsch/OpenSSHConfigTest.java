package com.jcraft.jsch;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class OpenSSHConfigTest {

  Map<String, String> keyMap = OpenSSHConfig.getKeymap().entrySet().stream().collect(Collectors
      .toMap(entry -> entry.getValue().toUpperCase(Locale.ROOT), Map.Entry::getKey, (s, s2) -> s2));

  @Test
  void parseFile() throws IOException, URISyntaxException {
    final String configFile =
        Paths.get(ClassLoader.getSystemResource("config").toURI()).toFile().getAbsolutePath();
    final OpenSSHConfig openSSHConfig = OpenSSHConfig.parseFile(configFile);
    final ConfigRepository.Config config = openSSHConfig.getConfig("host2");
    assertNotNull(config);
    assertEquals("foobar", config.getUser());
    assertEquals("host2.somewhere.edu", config.getHostname());
    assertEquals("~/.ssh/old_keys/host2_key", config.getValue("IdentityFile"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"MACs", "Macs"})
  void parseMacsCaseInsensitive(String key) throws IOException {
    OpenSSHConfig parse = OpenSSHConfig.parse(key + " someValue");
    ConfigRepository.Config config = parse.getConfig("");
    assertEquals("someValue", config.getValue("mac.c2s"));
    assertEquals("someValue", config.getValue("mac.s2c"));
  }

  @Test
  void appendKexAlgorithms() throws IOException {
    OpenSSHConfig parse = OpenSSHConfig.parse("KexAlgorithms +diffie-hellman-group1-sha1");
    ConfigRepository.Config kex = parse.getConfig("");
    assertEquals(JSch.getConfig("kex") + "," + "diffie-hellman-group1-sha1", kex.getValue("kex"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"KexAlgorithms", "Ciphers", "HostKeyAlgorithms", "MACs",
      "PubkeyAcceptedAlgorithms", "PubkeyAcceptedKeyTypes"})
  void appendAlgorithms(String key) throws IOException {
    OpenSSHConfig parse = OpenSSHConfig.parse(key + " +someValue,someValue1");
    ConfigRepository.Config config = parse.getConfig("");
    String mappedKey = Optional.ofNullable(keyMap.get(key.toUpperCase(Locale.ROOT))).orElse(key);
    assertEquals(JSch.getConfig(mappedKey) + "," + "someValue,someValue1",
        config.getValue(mappedKey));
  }

  @ParameterizedTest
  @ValueSource(strings = {"KexAlgorithms", "Ciphers", "HostKeyAlgorithms", "MACs",
      "PubkeyAcceptedAlgorithms", "PubkeyAcceptedKeyTypes"})
  void prependAlgorithms(String key) throws IOException {
    OpenSSHConfig parse = OpenSSHConfig.parse(key + " ^someValue,someValue1");
    ConfigRepository.Config config = parse.getConfig("");
    String mappedKey = Optional.ofNullable(keyMap.get(key.toUpperCase(Locale.ROOT))).orElse(key);
    assertEquals("someValue,someValue1," + JSch.getConfig(mappedKey), config.getValue(mappedKey));
  }

  @Test
  void prependKexAlgorithms() throws IOException {
    OpenSSHConfig parse = OpenSSHConfig.parse("KexAlgorithms ^diffie-hellman-group1-sha1");
    ConfigRepository.Config kex = parse.getConfig("");
    assertEquals("diffie-hellman-group1-sha1," + JSch.getConfig("kex"), kex.getValue("kex"));
  }

  @Test
  void removeKexAlgorithm() throws IOException {
    OpenSSHConfig parse = OpenSSHConfig.parse("KexAlgorithms -ecdh-sha2-nistp256");
    ConfigRepository.Config kex = parse.getConfig("");
    assertEquals(JSch.getConfig("kex").replaceAll(",ecdh-sha2-nistp256", ""), kex.getValue("kex"));
  }

  @Test
  void replaceKexAlgorithms() throws IOException {
    OpenSSHConfig parse = OpenSSHConfig.parse("KexAlgorithms diffie-hellman-group1-sha1");
    ConfigRepository.Config kex = parse.getConfig("");
    assertEquals("diffie-hellman-group1-sha1", kex.getValue("kex"));
  }

}
