package gui;

import javax.swing.*;
import java.awt.*;

public class LoginFrame extends JFrame {

    private final JTextField usernameField;
    private final JPasswordField passwordField;

    public LoginFrame() {

        setTitle("Cyber Threat Intelligence System");

        setSize(500, 450);

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        setLocationRelativeTo(null);

        setResizable(false);

        // Main Panel
        JPanel panel = new JPanel();

        panel.setBackground(new Color(15, 23, 42));

        panel.setLayout(null);

        // Application Title
        JLabel title = new JLabel("CYBER INTELLIGENCE");

        title.setBounds(90, 50, 350, 40);

        title.setForeground(Color.WHITE);

        title.setFont(new Font("Arial", Font.BOLD, 24));

        panel.add(title);

        // Subtitle
        JLabel subtitle = new JLabel(
                "EARLY DETECTION OF EMERGING CYBER THREATS");

        subtitle.setBounds(55, 100, 400, 25);

        subtitle.setForeground(new Color(148, 163, 184));

        subtitle.setFont(new Font("Arial", Font.PLAIN, 11));

        panel.add(subtitle);

        // Username Label
        JLabel usernameLabel = new JLabel("Username");

        usernameLabel.setBounds(80, 160, 120, 25);

        usernameLabel.setForeground(Color.WHITE);

        panel.add(usernameLabel);

        // Username Field
        usernameField = new JTextField();

        usernameField.setBounds(80, 190, 330, 35);

        panel.add(usernameField);

        // Password Label
        JLabel passwordLabel = new JLabel("Password");

        passwordLabel.setBounds(80, 240, 120, 25);

        passwordLabel.setForeground(Color.WHITE);

        panel.add(passwordLabel);

        // Password Field
        passwordField = new JPasswordField();

        passwordField.setBounds(80, 270, 330, 35);

        panel.add(passwordField);

        // Login Button
        JButton loginButton = new JButton("LOGIN");

        loginButton.setBounds(80, 330, 330, 40);

        loginButton.setBackground(new Color(37, 99, 235));

        loginButton.setForeground(Color.WHITE);

        loginButton.setFont(new Font("Arial", Font.BOLD, 14));

        panel.add(loginButton);

        // Login Action
        loginButton.addActionListener(e -> login());

        add(panel);

    }

    private void login() {

        String username = usernameField.getText();

        String password = new String(
                passwordField.getPassword());

        if (username.equals("admin")
                && password.equals("admin123")) {

            JOptionPane.showMessageDialog(
                    this,
                    "Login Successful!"
            );

            new Dashboard().setVisible(true);

            dispose();

        } else {

            JOptionPane.showMessageDialog(
                    this,
                    "Invalid Username or Password!"
            );

        }

    }

}