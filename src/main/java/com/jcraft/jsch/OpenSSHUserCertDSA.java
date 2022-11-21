package com.jcraft.jsch;

public class OpenSSHUserCertDSA extends KeyPairDSA implements OpenSSHCertifiedKey {
    private static final String keyType = "ssh-dss-cert-v01@openssh.com";
    private static final byte[] sshdsacert = Util.str2byte(keyType);

    public OpenSSHUserCertDSA(JSch jsch){
        super(jsch);
    }

    public int getCertificateType() {
        return SSH_CERT_TYPE_USER;
    }

    @Override
    public int getKeyType(){
        return DSA_CERT;
    }

    @Override
    byte[] getKeyTypeName(){
        return sshdsacert;
    }
}