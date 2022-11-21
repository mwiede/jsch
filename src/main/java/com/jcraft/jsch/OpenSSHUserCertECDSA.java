package com.jcraft.jsch;

public class OpenSSHUserCertECDSA extends KeyPairECDSA implements OpenSSHCertifiedKey {
    private static final String keyType = "ecdsa-sha2-nistp256-cert-v01@openssh.com";
    private static final byte[] sshrsacert = Util.str2byte(keyType);

    public OpenSSHUserCertECDSA(JSch jsch){
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