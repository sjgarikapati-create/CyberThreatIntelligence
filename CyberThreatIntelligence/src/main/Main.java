package main;

import database.DatabaseSetup;
import gui.LoginFrame;
import javax.swing.SwingUtilities;

public class Main {

    public static void main(String[] args) {

        // Create database tables
        DatabaseSetup.createTables();

        // Launch application
        SwingUtilities.invokeLater(() -> {

            LoginFrame login = new LoginFrame();

            login.setVisible(true);

        });

    }

}