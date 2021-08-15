package com.jcraft.jsch;

import org.junit.jupiter.api.Test;

import java.util.Hashtable;

import static org.junit.jupiter.api.Assertions.*;

class JSchTest {

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
}
