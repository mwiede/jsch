package com.jcraft.jsch;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class OpenSSHConfigTest {

    @org.junit.jupiter.api.Test
    void parseFile() throws IOException, URISyntaxException {
        final String configFile = Paths.get(ClassLoader.getSystemResource("config").toURI()).toFile().getAbsolutePath();
        final OpenSSHConfig openSSHConfig = OpenSSHConfig.parseFile(configFile);
        final ConfigRepository.Config config = openSSHConfig.getConfig("host2");
        assertNotNull(config);
        assertEquals("foobar", config.getUser());
        assertEquals("host2.somewhere.edu", config.getHostname());
        assertEquals("~/.ssh/old_keys/host2_key",config.getValue("IdentityFile"));
    }
}