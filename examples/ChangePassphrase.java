/**
 * This program will demonstrate to change the passphrase for a private key file instead of creating
 * a new private key. A passphrase will be prompted if the given private-key has been encrypted.
 * After successfully loading the content of the private-key, the new passphrase will be prompted
 * and the given private-key will be re-encrypted with that new passphrase.
 *
 */
import com.jcraft.jsch.*;
import javax.swing.*;

public class ChangePassphrase {
  public static void main(String[] arg) {
    if (arg.length != 1) {
      System.err.println("usage: java ChangePassphrase private_key");
      System.exit(-1);
    }

    JSch jsch = new JSch();

    String pkey = arg[0];

    try {
      KeyPair kpair = KeyPair.load(jsch, pkey);

      System.out
          .println(pkey + " has " + (kpair.isEncrypted() ? "been " : "not been ") + "encrypted");

      String passphrase = "";
      while (kpair.isEncrypted()) {
        JTextField passphraseField = new JPasswordField(20);
        Object[] ob = {passphraseField};
        int result = JOptionPane.showConfirmDialog(null, ob, "Enter passphrase for " + pkey,
            JOptionPane.OK_CANCEL_OPTION);
        if (result != JOptionPane.OK_OPTION) {
          System.exit(-1);
        }
        passphrase = passphraseField.getText();
        if (!kpair.decrypt(passphrase)) {
          System.out.println("failed to decrypt " + pkey);
        } else {
          System.out.println(pkey + " is decrypted.");
        }
      }

      passphrase = "";

      JTextField passphraseField = new JPasswordField(20);
      Object[] ob = {passphraseField};
      int result = JOptionPane.showConfirmDialog(null, ob,
          "Enter new passphrase for " + pkey + " (empty for no passphrase)",
          JOptionPane.OK_CANCEL_OPTION);
      if (result != JOptionPane.OK_OPTION) {
        System.exit(-1);
      }
      passphrase = passphraseField.getText();

      kpair.writePrivateKey(pkey, passphrase.getBytes());
      kpair.dispose();
    } catch (Exception e) {
      System.out.println(e);
    }
    System.exit(0);
  }
}
