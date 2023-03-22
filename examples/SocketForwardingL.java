/**
 * This program enables you to connect to sshd server and forward the docker socket. You will be
 * asked username, hostname and passwd. If everything works fine, you will get the response code to
 * the _ping endpoint of the dockerd.
 *
 */
import com.jcraft.jsch.*;

import javax.swing.*;
import java.net.HttpURLConnection;
import java.net.URL;

public class SocketForwardingL {
  public static void main(String[] arg) {

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

      String passwd = JOptionPane.showInputDialog("Enter password");
      session.setPassword(passwd);

      UserInfo ui = new MyUserInfo() {
        @Override
        public void showMessage(String message) {
          JOptionPane.showMessageDialog(null, message);
        }

        @Override
        public boolean promptYesNo(String message) {
          Object[] options = {"yes", "no"};
          int foo = JOptionPane.showOptionDialog(null, message, "Warning",
              JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[0]);
          return foo == 0;
        }

        // If password is not given before the invocation of Session#connect(),
        // implement also following methods,
        // * UserInfo#getPassword(),
        // * UserInfo#promptPassword(String message) and
        // * UIKeyboardInteractive#promptKeyboardInteractive()

      };

      session.setUserInfo(ui);

      // It must not be recommended, but if you want to skip host-key check,
      // invoke following,
      // session.setConfig("StrictHostKeyChecking", "no");

      // session.connect();
      session.connect(30000); // making a connection with timeout.

      final int boundPort =
          session.setSocketForwardingL(null, 0, "/var/run/docker.sock", null, 1000);

      URL myURL = new URL("http://localhost:" + boundPort + "/_ping");
      HttpURLConnection myURLConnection = (HttpURLConnection) myURL.openConnection();
      System.out.println(
          "Docker Ping http response code (" + myURL + "): " + myURLConnection.getResponseCode());

      session.disconnect();

      HttpURLConnection myURLConnection2 = (HttpURLConnection) myURL.openConnection();
      System.out.println("Docker Ping http response code: " + myURLConnection2.getResponseCode());


    } catch (Exception e) {
      System.out.println(e);
    }
  }

  public static abstract class MyUserInfo implements UserInfo, UIKeyboardInteractive {
    @Override
    public String getPassword() {
      return null;
    }

    @Override
    public String getPassphrase() {
      return null;
    }

    @Override
    public boolean promptPassphrase(String message) {
      return false;
    }

    @Override
    public boolean promptPassword(String message) {
      return false;
    }

    @Override
    public String[] promptKeyboardInteractive(String destination, String name, String instruction,
        String[] prompt, boolean[] echo) {
      return null;
    }
  }
}
