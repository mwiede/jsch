/**
 * This program will demonstrate SSH through jump hosts. Suppose that you don't have direct accesses
 * to host2 and host3. java JumpHosts usr1@host1 usr2@host2 usr3@host3. You will be asked passwords
 * for those destinations. If everything works fine, you will get file lists of your home-directory
 * at host3.
 *
 */
import com.jcraft.jsch.*;
import java.awt.*;
import javax.swing.*;

public class JumpHosts {
  public static void main(String[] arg) {

    try {
      JSch jsch = new JSch();

      if (arg.length <= 1) {
        System.out.println("This program expects more arguments.");
        System.exit(-1);
      }

      Session session = null;
      Session[] sessions = new Session[arg.length];

      String host = arg[0];
      String user = host.substring(0, host.indexOf('@'));
      host = host.substring(host.indexOf('@') + 1);

      sessions[0] = session = jsch.getSession(user, host, 22);
      session.setUserInfo(new MyUserInfo());
      session.connect();
      System.out.println("The session has been established to " + user + "@" + host);

      for (int i = 1; i < arg.length; i++) {
        host = arg[i];
        user = host.substring(0, host.indexOf('@'));
        host = host.substring(host.indexOf('@') + 1);

        int assinged_port = session.setPortForwardingL(0, host, 22);
        System.out
            .println("portforwarding: " + "localhost:" + assinged_port + " -> " + host + ":" + 22);
        sessions[i] = session = jsch.getSession(user, "127.0.0.1", assinged_port);

        session.setUserInfo(new MyUserInfo());
        session.setHostKeyAlias(host);
        session.connect();
        System.out.println("The session has been established to " + user + "@" + host);
      }

      ChannelSftp sftp = (ChannelSftp) session.openChannel("sftp");

      sftp.connect();
      sftp.ls(".", new ChannelSftp.LsEntrySelector() {
        @Override
        public int select(ChannelSftp.LsEntry le) {
          System.out.println(le);
          return ChannelSftp.LsEntrySelector.CONTINUE;
        }
      });
      sftp.disconnect();

      for (int i = sessions.length - 1; i >= 0; i--) {
        sessions[i].disconnect();
      }
    } catch (Exception e) {
      System.out.println(e);
    }
  }

  public static class MyUserInfo implements UserInfo, UIKeyboardInteractive {
    @Override
    public String getPassword() {
      return passwd;
    }

    @Override
    public boolean promptYesNo(String str) {
      Object[] options = {"yes", "no"};
      int foo = JOptionPane.showOptionDialog(null, str, "Warning", JOptionPane.DEFAULT_OPTION,
          JOptionPane.WARNING_MESSAGE, null, options, options[0]);
      return foo == 0;
    }

    String passwd;
    JTextField passwordField = new JPasswordField(20);

    @Override
    public String getPassphrase() {
      return null;
    }

    @Override
    public boolean promptPassphrase(String message) {
      return true;
    }

    @Override
    public boolean promptPassword(String message) {
      Object[] ob = {passwordField};
      int result = JOptionPane.showConfirmDialog(null, ob, message, JOptionPane.OK_CANCEL_OPTION);
      if (result == JOptionPane.OK_OPTION) {
        passwd = passwordField.getText();
        return true;
      } else {
        return false;
      }
    }

    @Override
    public void showMessage(String message) {
      JOptionPane.showMessageDialog(null, message);
    }

    final GridBagConstraints gbc = new GridBagConstraints(0, 0, 1, 1, 1, 1,
        GridBagConstraints.NORTHWEST, GridBagConstraints.NONE, new Insets(0, 0, 0, 0), 0, 0);
    private Container panel;

    @Override
    public String[] promptKeyboardInteractive(String destination, String name, String instruction,
        String[] prompt, boolean[] echo) {
      panel = new JPanel();
      panel.setLayout(new GridBagLayout());

      gbc.weightx = 1.0;
      gbc.gridwidth = GridBagConstraints.REMAINDER;
      gbc.gridx = 0;
      panel.add(new JLabel(instruction), gbc);
      gbc.gridy++;

      gbc.gridwidth = GridBagConstraints.RELATIVE;

      JTextField[] texts = new JTextField[prompt.length];
      for (int i = 0; i < prompt.length; i++) {
        gbc.fill = GridBagConstraints.NONE;
        gbc.gridx = 0;
        gbc.weightx = 1;
        panel.add(new JLabel(prompt[i]), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weighty = 1;
        if (echo[i]) {
          texts[i] = new JTextField(20);
        } else {
          texts[i] = new JPasswordField(20);
        }
        panel.add(texts[i], gbc);
        gbc.gridy++;
      }

      if (JOptionPane.showConfirmDialog(null, panel, destination + ": " + name,
          JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE) == JOptionPane.OK_OPTION) {
        String[] response = new String[prompt.length];
        for (int i = 0; i < prompt.length; i++) {
          response[i] = texts[i].getText();
        }
        return response;
      } else {
        return null; // cancel
      }
    }
  }
}
