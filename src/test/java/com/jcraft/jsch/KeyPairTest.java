package com.jcraft.jsch;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyPairTest {

    @BeforeAll
    static void init() {
        JSch.setLogger(Slf4jLogger.getInstance());
    }

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
                // ecdsa EC private key format
                Arguments.of("docker/id_ecdsa256", null, null), //
                Arguments.of("docker/id_ecdsa384", null, null), //
                Arguments.of("docker/id_ecdsa521", null, null),
                Arguments.of("docker/ssh_host_ecdsa256_key", null, null),
                Arguments.of("docker/ssh_host_ecdsa384_key", null, null),
                Arguments.of("docker/ssh_host_ecdsa521_key", null, null),
                // encrypted ecdsa
                Arguments.of("encrypted_openssh_private_key_ecdsa", "secret123", null)

        );
    }

    @ParameterizedTest
    @MethodSource("keyArgs")
    void loadKey(String path, String password, String publicKeyType) throws URISyntaxException, JSchException {
        final JSch jSch = new JSch();
        final String prvkey = Paths.get(ClassLoader.getSystemResource(path).toURI()).toFile().getAbsolutePath();
        assertTrue(new File(prvkey).exists());
        assertDoesNotThrow(() -> {
            if (null != password) {
                jSch.addIdentity(prvkey, password);
            } else {
                jSch.addIdentity(prvkey);
            }
        });
    }

    @Test
    void genKeypair() {
        final JSch jSch = new JSch();
        assertDoesNotThrow(() -> {
            KeyPair kpair = KeyPair.genKeyPair(jSch, KeyPair.RSA, 1024);
            kpair.writePrivateKey(System.getProperty("java.io.tmpdir") + File.separator + "my-private-key");
        });
    }

    @Test
    void genKeypairEncrypted() {
        final JSch jSch = new JSch();
        assertDoesNotThrow(() -> {
            KeyPair kpair = KeyPair.genKeyPair(jSch, KeyPair.RSA, 1024);
            kpair.writePrivateKey(System.getProperty("java.io.tmpdir") + File.separator + "my-private-key-encrypted",
                    "my-password".getBytes());
        });
    }

}