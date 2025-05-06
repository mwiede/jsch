/**
 * This progam will demonstrate the keypair generation. You will be asked a passphrase for
 * output_keyfile. If everything works fine, you will get the keypair, output_keyfile and
 * output_keyfile+".pub". The private key and public key are in the OpenSSH v1 format.
 */
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.KeyPair;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

public class KeyGenOpenSSHv1 {
  public static void main(String[] arg) {
    int key_size = 1024;
    if (arg.length < 3) {
      System.err.println("usage: java KeyGenOpenSSHv1 rsa output_keyfile comment\n"
          + "       java KeyGenOpenSSHv1 dsa output_keyfile comment\n"
          + "       java KeyGenOpenSSHv1 ecdsa-sha2-256 output_keyfile comment\n"
          + "       java KeyGenOpenSSHv1 ecdsa-sha2-384 output_keyfile comment\n"
          + "       java KeyGenOpenSSHv1 ecdsa-sha2-521 output_keyfile comment\n"
          + "       java KeyGenOpenSSHv1 ed25519 output_keyfile comment\n"
          + "       java KeyGenOpenSSHv1 ed448 output_keyfile comment");
      System.exit(-1);
    }
    String _type = arg[0];
    int type = 0;
    if (_type.equals("rsa")) {
      type = KeyPair.RSA;
    } else if (_type.equals("dsa")) {
      type = KeyPair.DSA;
    } else if (_type.equals("ecdsa-sha2-nistp256")) {
      type = KeyPair.ECDSA;
      key_size = 256;
    } else if (_type.equals("ecdsa-sha2-nistp384")) {
      type = KeyPair.ECDSA;
      key_size = 384;
    } else if (_type.equals("ecdsa-sha2-nistp521")) {
      type = KeyPair.ECDSA;
      key_size = 521;
    } else if (_type.equals("ed25519")) {
      type = KeyPair.ED25519;
      key_size = 0;
    } else if (_type.equals("ed448")) {
      type = KeyPair.ED448;
      key_size = 0;
    } else {
      System.err.println("usage: java KeyGenOpenSSHv1 rsa output_keyfile comment\n"
          + "       java KeyGenOpenSSHv1 dsa output_keyfile comment\n"
          + "       java KeyGenOpenSSHv1 ecdsa-sha2-256 output_keyfile comment\n"
          + "       java KeyGenOpenSSHv1 ecdsa-sha2-384 output_keyfile comment\n"
          + "       java KeyGenOpenSSHv1 ecdsa-sha2-521 output_keyfile comment\n"
          + "       java KeyGenOpenSSHv1 ed25519 output_keyfile comment\n"
          + "       java KeyGenOpenSSHv1 ed448 output_keyfile comment");
      System.exit(-1);
    }
    String filename = arg[1];
    String comment = arg[2];

    JSch jsch = new JSch();

    String passphrase = "";
    JTextField passphraseField = new JPasswordField(20);
    Object[] ob = {passphraseField};
    int result = JOptionPane.showConfirmDialog(null, ob,
        "Enter passphrase (empty for no passphrase)", JOptionPane.OK_CANCEL_OPTION);
    if (result == JOptionPane.OK_OPTION) {
      passphrase = passphraseField.getText();
    }

    try {
      KeyPair kpair = KeyPair.genKeyPair(jsch, type, key_size);
      kpair.writeOpenSSHv1PrivateKey(filename, passphrase.getBytes());
      kpair.writePublicKey(filename + ".pub", comment);
      System.out.println("Finger print: " + kpair.getFingerPrint());
      kpair.dispose();
    } catch (Exception e) {
      System.out.println(e);
    }
    System.exit(0);
  }
}
