import com.jcraft.jsch.*;
import java.io.*;
import javax.swing.*;

public class JSchWithAgentProxy {
  public static void main(String[] arg) {

    try {
      JSch jsch = new JSch();

      // IdentityRepository irepo = new AgentIdentityRepository(new PageantConnector());
      IdentityRepository irepo = new AgentIdentityRepository(new SSHAgentConnector());
      jsch.setIdentityRepository(irepo);

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
      session.setConfig("PreferredAuthentications", "publickey");

      // username and passphrase will be given via UserInfo interface.
      UserInfo ui = new MyUserInfo();
      session.setUserInfo(ui);
      session.connect();

      Channel channel = session.openChannel("shell");

      ((ChannelShell) channel).setAgentForwarding(true);

      channel.setInputStream(System.in);
      channel.setOutputStream(System.out);

      channel.connect();

    } catch (Exception e) {
      System.out.println(e);
    }
  }

  public static class MyUserInfo implements UserInfo, UIKeyboardInteractive {
    String passwd = null;

    @Override
    public String getPassword() {
      return passwd;
    }

    @Override
    public boolean promptYesNo(String str) {
      return true;
    }

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
      return true;
    }

    @Override
    public void showMessage(String message) {}

    @Override
    public String[] promptKeyboardInteractive(String destination, String name, String instruction,
        String[] prompt, boolean[] echo) {
      String[] response = new String[prompt.length];
      response[0] = passwd;
      return response;
    }
  }
}
