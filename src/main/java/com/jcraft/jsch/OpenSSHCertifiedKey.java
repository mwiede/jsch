package com.jcraft.jsch;

public interface OpenSSHCertifiedKey {
        int SSH_CERT_TYPE_USER  =  1;
        int SSH_CERT_TYPE_HOST  =  2;
        int getCertificateType();
}
