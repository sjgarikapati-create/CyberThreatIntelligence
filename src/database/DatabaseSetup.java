package database;

import java.sql.Connection;
import java.sql.Statement;
import java.sql.SQLException;

public class DatabaseSetup {

    public static void createTables() {

        String threatsTable = """
            CREATE TABLE IF NOT EXISTS Threats (
                threat_id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_name TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT,
                description TEXT
            )
        """;

        String eventsTable = """
            CREATE TABLE IF NOT EXISTS ThreatEvents (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id INTEGER,
                event_date TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                FOREIGN KEY (threat_id)
                REFERENCES Threats(threat_id)
            )
        """;

        String alertsTable = """
            CREATE TABLE IF NOT EXISTS Alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id INTEGER,
                alert_date TEXT NOT NULL,
                risk_level TEXT,
                message TEXT,
                FOREIGN KEY (threat_id)
                REFERENCES Threats(threat_id)
            )
        """;

        String groundTruthTable = """
            CREATE TABLE IF NOT EXISTS GroundTruth (
                ground_truth_id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id INTEGER NOT NULL UNIQUE,
                actual_status TEXT NOT NULL
                CHECK(actual_status IN ('EMERGING', 'NORMAL')),
                FOREIGN KEY (threat_id)
                REFERENCES Threats(threat_id)
            )
        """;

        try (Connection connection =
                DatabaseConnection.getConnection()) {

            if (connection == null) {
                System.out.println("Database Connection Failed!");
                return;
            }

            try (Statement statement = connection.createStatement()) {

                statement.execute(threatsTable);
                statement.execute(eventsTable);
                statement.execute(alertsTable);
                statement.execute(groundTruthTable);

                System.out.println("Threats Table Created!");
                System.out.println("Threat Events Table Created!");
                System.out.println("Alerts Table Created!");
                System.out.println("GroundTruth Table Created!");
            }

        } catch (SQLException e) {

            System.out.println("Table Creation Failed!");
            System.out.println(e.getMessage());
        }
    }
}