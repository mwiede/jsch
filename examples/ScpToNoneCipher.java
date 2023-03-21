/**
 * This program will demonstrate how to enable none cipher. You will be asked passwd. If everything
 * works fine, a local file 'file1' will copied to 'file2' on 'remotehost'.
 *
 */
import com.jcraft.jsch.*;
import java.awt.*;
import javax.swing.*;
import java.io.*;

public class ScpToNoneCipher {
  public static void main(String[] arg) {
    if (arg.length != 2) {
      System.err.println("usage: java ScpTo file1 user@remotehost:file2");
      System.exit(-1);
    }

    try {

      String lfile = arg[0];
      String user = arg[1].substring(0, arg[1].indexOf('@'));
      arg[1] = arg[1].substring(arg[1].indexOf('@') + 1);
      String host = arg[1].substring(0, arg[1].indexOf(':'));
      String rfile = arg[1].substring(arg[1].indexOf(':') + 1);

      JSch jsch = new JSch();
      Session session = jsch.getSession(user, host, 22);

      // username and password will be given via UserInfo interface.
      UserInfo ui = new MyUserInfo();
      session.setUserInfo(ui);
      session.connect();

      session.setConfig("cipher.s2c", "none,aes128-cbc,3des-cbc,blowfish-cbc");
      session.setConfig("cipher.c2s", "none,aes128-cbc,3des-cbc,blowfish-cbc");

      session.rekey();

      // exec 'scp -t rfile' remotely
      rfile = rfile.replace("'", "'\"'\"'");
      rfile = "'" + rfile + "'";
      String command = "scp -p -t " + rfile;
      Channel channel = session.openChannel("exec");
      ((ChannelExec) channel).setCommand(command);

      // get I/O streams for remote scp
      OutputStream out = channel.getOutputStream();
      InputStream in = channel.getInputStream();

      channel.connect();

      if (checkAck(in) != 0) {
        System.exit(0);
      }

      File _lfile = new File(lfile);

      command = "T " + (_lfile.lastModified() / 1000) + " 0";
      // The access time should be sent here,
      // but it is not accessible with JavaAPI ;-<
      command += " " + (_lfile.lastModified() / 1000) + " 0\n";
      out.write(command.getBytes());
      out.flush();
      if (checkAck(in) != 0) {
        System.exit(0);
      }

      // send "C0644 filesize filename", where filename should not include '/'
      long filesize = _lfile.length();
      command = "C0644 " + filesize + " ";
      if (lfile.lastIndexOf('/') > 0) {
        command += lfile.substring(lfile.lastIndexOf('/') + 1);
      } else {
        command += lfile;
      }
      command += "\n";
      out.write(command.getBytes());
      out.flush();

      if (checkAck(in) != 0) {
        System.exit(0);
      }

      byte[] buf = new byte[1024];

      // send a content of lfile
      try (InputStream fis = new FileInputStream(lfile)) {
        while (true) {
          int len = fis.read(buf, 0, buf.length);
          if (len <= 0)
            break;
          out.write(buf, 0, len);
          // out.flush();
        }
      }

      // send '\0'
      buf[0] = 0;
      out.write(buf, 0, 1);
      out.flush();

      if (checkAck(in) != 0) {
        System.exit(0);
      }

      session.disconnect();

      System.exit(0);
    } catch (Exception e) {
      System.out.println(e);
    }
  }

  static int checkAck(InputStream in) throws IOException {
    int b = in.read();
    // b may be 0 for success,
    // 1 for error,
    // 2 for fatal error,
    // -1
    if (b == 0)
      return b;
    if (b == -1)
      return b;

    if (b == 1 || b == 2) {
      StringBuilder sb = new StringBuilder();
      int c;
      do {
        c = in.read();
        sb.append((char) c);
      } while (c != '\n');
      if (b == 1) { // error
        System.out.print(sb);
      }
      if (b == 2) { // fatal error
        System.out.print(sb);
      }
    }
    return b;
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
