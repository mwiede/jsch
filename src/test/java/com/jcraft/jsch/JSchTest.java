package com.jcraft.jsch;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Hashtable;

import static org.junit.jupiter.api.Assertions.*;

class JSchTest {
    private Hashtable<String, String> orgConfig;
    private Logger orgLogger;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void resetJsch() {
      orgConfig = (Hashtable<String, String>) JSch.config.clone();
      orgLogger = JSch.getLogger();
      JSch.setLogger(null);
    }

    @AfterEach
    void restoreConfig() {
      JSch.setConfig(orgConfig);
      JSch.setLogger(orgLogger);
    }
    
    @Test
    void getPubkeyAcceptedKeyTypes() throws JSchException {
        JSch.setConfig("PubkeyAcceptedAlgorithms", "JSchTest111");
        assertEquals("JSchTest111", JSch.getConfig("PubkeyAcceptedKeyTypes"));
        assertEquals("JSchTest111", JSch.getConfig("PubkeyAcceptedAlgorithms"));
    }

    @Test
    void setPubkeyAcceptedKeyTypes() throws JSchException {
        JSch.setConfig("PubkeyAcceptedKeyTypes", "JSchTest222");
        assertEquals("JSchTest222", JSch.getConfig("PubkeyAcceptedKeyTypes"));
        assertEquals("JSchTest222", JSch.getConfig("PubkeyAcceptedAlgorithms"));
    }

    @Test
    void setPubkeyAcceptedKeyTypesHashtable() throws JSchException {
        Hashtable<String, String> newconf = new Hashtable<>();
        newconf.put("PubkeyAcceptedKeyTypes", "JSchTest333");
        JSch.setConfig(newconf);
        assertEquals("JSchTest333", JSch.getConfig("PubkeyAcceptedKeyTypes"));
        assertEquals("JSchTest333", JSch.getConfig("PubkeyAcceptedAlgorithms"));
    }
    
    @Test
    void clientVersionSetting() throws Exception {
      String orgConfig = JSch.getConfig("client_version");
      assertEquals("SSH-2.0-JSCH_" + Version.getVersion(), orgConfig, "client version in Config differs");
      
      System.setProperty("jsch.client_version", "My personal client version");
      Hashtable<String, String> map = new Hashtable<>();
      JSch.fillConfig(map, 1);
      System.getProperties().remove("jsch.client_version");
      JSch.setConfig(map);
      assertEquals("My personal client version", JSch.getConfig("client_version"), "client version in Config differs");
      
      JSch jsch = new JSch();
      assertEquals("My personal client version", jsch.getClientVersion(), "client version in Config differs");
      jsch.setClientVersion("SSH-2.0-JSCH_OpenSSH_notreally_client");
      assertEquals("SSH-2.0-JSCH_OpenSSH_notreally_client", jsch.getClientVersion(), "client version in Config differs");
      assertEquals("My personal client version", new JSch().getClientVersion(), "expected global client for new instance");
      jsch.setClientVersion(null);
      assertEquals("My personal client version", jsch.getClientVersion(), "client version in Config differs");
    }
    
    @Test
    void checkLoggerBehavior() throws Exception {
        assertSame(JSch.DEVNULL, JSch.logger, "initial static value of logger should be DEVNULL");

        JSch jsch = new JSch();
        assertSame(JSch.DEVNULL, jsch.getInstanceLogger(), "instance logger should be DEVNULL");
        
        TestLogger staticLogger = new TestLogger();
        TestLogger instanceLogger = new TestLogger();
        
        JSch.setLogger(staticLogger);
        assertSame(staticLogger, JSch.logger, "mismatch with static logger");
        assertSame(staticLogger, jsch.getInstanceLogger(), "instance should return static logger");
        
        jsch.setInstanceLogger(instanceLogger);
        assertSame(staticLogger, JSch.logger, "mismatch with static logger");
        assertSame(instanceLogger, jsch.getInstanceLogger(), "instance should return static logger");
        
        jsch.setInstanceLogger(null);
        assertSame(staticLogger, JSch.logger, "mismatch with static logger");
        assertSame(staticLogger, jsch.getInstanceLogger(), "instance should return static logger");
        
        JSch.setLogger(null);
        assertSame(JSch.DEVNULL, JSch.logger, "static logger should be DEVNULL");
        assertSame(JSch.DEVNULL, jsch.getInstanceLogger(), "instance logger should be DEVNULL");
    }
    
    final static class TestLogger implements Logger {
        @Override
        public boolean isEnabled(int level) {
            return true;
        }

        @Override
        public void log(int level, String message) {
            // empty
        }
    }
}
