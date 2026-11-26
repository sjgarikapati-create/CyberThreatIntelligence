package dao;

import database.DatabaseConnection;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class GroundTruthDAO {

    // =====================================
    // SYNTHETIC GROUND TRUTH
    // =====================================

    public void createTable() {

        String sql = """
            CREATE TABLE IF NOT EXISTS GroundTruth (
                ground_truth_id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id INTEGER NOT NULL UNIQUE,
                actual_status TEXT NOT NULL
                CHECK(actual_status IN ('EMERGING', 'NORMAL')),
                FOREIGN KEY (threat_id)
                REFERENCES Threats(threat_id)
            )
            """;

        executeTableCreation(sql, "GroundTruth");
    }

    public boolean addGroundTruth(int threatId, String actualStatus) {

        if (!isValidStatus(actualStatus)) {
            return false;
        }

        String sql = """
            INSERT INTO GroundTruth (threat_id, actual_status)
            VALUES (?, ?)
            ON CONFLICT(threat_id)
            DO UPDATE SET actual_status = excluded.actual_status
            """;

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                return false;
            }

            try (PreparedStatement pst = con.prepareStatement(sql)) {

                pst.setInt(1, threatId);
                pst.setString(2, actualStatus);

                pst.executeUpdate();
                return true;
            }

        } catch (SQLException e) {
            System.out.println("Ground truth error: " + e.getMessage());
            return false;
        }
    }

    // =====================================
    // CISA GROUND TRUTH
    // =====================================

    public void createCISAGroundTruthTable() {

        String sql = """
            CREATE TABLE IF NOT EXISTS CISAGroundTruth (
                ground_truth_id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL UNIQUE,
                actual_status TEXT NOT NULL
                CHECK(actual_status IN ('EMERGING', 'NORMAL')),
                FOREIGN KEY (cve_id)
                REFERENCES CISAVulnerabilities(cve_id)
            )
            """;

        executeTableCreation(sql, "CISAGroundTruth");
    }

    public boolean addCISAGroundTruth(
            String cveId,
            String actualStatus) {

        if (cveId == null || cveId.trim().isEmpty()
                || !isValidStatus(actualStatus)) {
            return false;
        }

        String sql = """
            INSERT INTO CISAGroundTruth (cve_id, actual_status)
            VALUES (?, ?)
            ON CONFLICT(cve_id)
            DO UPDATE SET actual_status = excluded.actual_status
            """;

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                return false;
            }

            try (PreparedStatement pst = con.prepareStatement(sql)) {

                pst.setString(1, cveId.trim());
                pst.setString(2, actualStatus);

                pst.executeUpdate();
                return true;
            }

        } catch (SQLException e) {
            System.out.println("CISA ground truth error: " + e.getMessage());
            return false;
        }
    }

    // =====================================
    // HELPER METHODS
    // =====================================

    private boolean isValidStatus(String status) {

        return "EMERGING".equals(status)
                || "NORMAL".equals(status);
    }

    private void executeTableCreation(String sql, String tableName) {

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                throw new SQLException("Database connection failed.");
            }

            try (PreparedStatement pst = con.prepareStatement(sql)) {

                pst.execute();

                System.out.println(
                        tableName + " table created successfully!"
                );
            }

        } catch (SQLException e) {
            System.out.println(tableName + " table error: " + e.getMessage());
        }
    }
}