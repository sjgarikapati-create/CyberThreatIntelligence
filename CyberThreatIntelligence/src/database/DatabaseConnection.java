package database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseConnection {

    private static final String URL =
            "jdbc:sqlite:cyber_threats.db";

    public static Connection getConnection() {

        Connection connection = null;

        try {

            connection = DriverManager.getConnection(URL);

            System.out.println("Database Connected Successfully!");

        } catch (SQLException e) {

            System.out.println("Database Connection Failed!");
            System.out.println(e.getMessage());

        }

        return connection;
    }
}