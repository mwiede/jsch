/**
 * This program will demonstrate the ssh session via HTTP proxy. $ CLASSPATH=.:../build javac
 * ViaHTTP.java $ CLASSPATH=.:../build java ViaHTTP You will be asked username, hostname,
 * proxy-server and passwd. If everything works fine, you will get the shell prompt.
 *
 */
import com.jcraft.jsch.*;
import java.awt.*;
import javax.swing.*;

public class ViaHTTP {
  public static void main(String[] arg) {

    String proxy_host;
    int proxy_port;

    try {
      JSch jsch = new JSch();

      String host = null;
      if (arg.length > 0) {
        host = arg[0];
      } else {
        host = JOptionPane.showInputDialog("Enter username@hostname",
            System.getProperty("user.name") + "@localhost");
      }
      String user = host.substring(0, host.indexOf('@'));
      host = host.substring(host.indexOf('@') + 1);

      Session session = jsch.getSession(user, host, 22);

      String proxy = JOptionPane.showInputDialog("Enter proxy server", "hostname:port");
      proxy_host = proxy.substring(0, proxy.indexOf(':'));
      proxy_port = Integer.parseInt(proxy.substring(proxy.indexOf(':') + 1));

      session.setProxy(new ProxyHTTP(proxy_host, proxy_port));

      // username and password will be given via UserInfo interface.
      UserInfo ui = new MyUserInfo();
      session.setUserInfo(ui);

      session.connect();

      Channel channel = session.openChannel("shell");

      channel.setInputStream(System.in);
      channel.setOutputStream(System.out);

      channel.connect();
    } catch (Exception e) {
      System.out.println(e);
    }
  }

  public static class MyUserInfo implements UserInfo, UIKeyboardInteractive {
    public String getPassword() {
      return passwd;
    }

    public boolean promptYesNo(String str) {
      Object[] options = {"yes", "no"};
      int foo = JOptionPane.showOptionDialog(null, str, "Warning", JOptionPane.DEFAULT_OPTION,
          JOptionPane.WARNING_MESSAGE, null, options, options[0]);
      return foo == 0;
    }

    String passwd;
    JTextField passwordField = (JTextField) new JPasswordField(20);

    public String getPassphrase() {
      return null;
    }

    public boolean promptPassphrase(String message) {
      return true;
    }

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

    public void showMessage(String message) {
      JOptionPane.showMessageDialog(null, message);
    }

    final GridBagConstraints gbc = new GridBagConstraints(0, 0, 1, 1, 1, 1,
        GridBagConstraints.NORTHWEST, GridBagConstraints.NONE, new Insets(0, 0, 0, 0), 0, 0);
    private Container panel;

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


