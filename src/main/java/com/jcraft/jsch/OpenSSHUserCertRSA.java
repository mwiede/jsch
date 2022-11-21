package com.jcraft.jsch;

/**
 *
 */
public class OpenSSHUserCertRSA extends KeyPairRSA implements OpenSSHCertifiedKey {
    private static final String keyType = "ssh-rsa-cert-v01@openssh.com";
    private static final byte[] sshrsacert = Util.str2byte(keyType);

    public OpenSSHUserCertRSA(JSch jsch){
        super(jsch);
    }

    public int getCertificateType() {
        return SSH_CERT_TYPE_USER;
    }

    @Override
    public int getKeyType(){
        return RSA_CERT;
    }

    @Override
    byte[] getKeyTypeName(){
        return sshrsacert;
    }

}