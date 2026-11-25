package dao;

import database.DatabaseConnection;
import model.Threat;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

public class ThreatDAO {

    // INSERT: Add a new threat
    public boolean addThreat(Threat threat) {

        String sql = "INSERT INTO Threats "
                + "(threat_name, category, severity, description) "
                + "VALUES (?, ?, ?, ?)";

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                return false;
            }

            try (PreparedStatement pst = con.prepareStatement(sql)) {

                pst.setString(1, threat.getThreatName());
                pst.setString(2, threat.getCategory());
                pst.setString(3, threat.getSeverity());
                pst.setString(4, threat.getDescription());

                pst.executeUpdate();

                return true;
            }

        } catch (SQLException e) {

            System.out.println("Error Adding Threat: " + e.getMessage());
            return false;
        }
    }

    // SELECT: Retrieve all threats
    public ArrayList<Threat> getAllThreats() {

        ArrayList<Threat> threats = new ArrayList<>();

        String sql = "SELECT * FROM Threats";

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                return threats;
            }

            try (PreparedStatement pst = con.prepareStatement(sql);
                 ResultSet rs = pst.executeQuery()) {

                while (rs.next()) {

                    Threat threat = new Threat(
                            rs.getInt("threat_id"),
                            rs.getString("threat_name"),
                            rs.getString("category"),
                            rs.getString("severity"),
                            rs.getString("description")
                    );

                    threats.add(threat);
                }
            }

        } catch (SQLException e) {

            System.out.println("Error Retrieving Threats: " + e.getMessage());
        }

        return threats;
    }

    // UPDATE: Modify an existing threat
    public boolean updateThreat(Threat threat) {

        String sql = "UPDATE Threats SET "
                + "threat_name=?, category=?, severity=?, description=? "
                + "WHERE threat_id=?";

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                return false;
            }

            try (PreparedStatement pst = con.prepareStatement(sql)) {

                pst.setString(1, threat.getThreatName());
                pst.setString(2, threat.getCategory());
                pst.setString(3, threat.getSeverity());
                pst.setString(4, threat.getDescription());
                pst.setInt(5, threat.getThreatId());

                return pst.executeUpdate() > 0;
            }

        } catch (SQLException e) {

            System.out.println("Error Updating Threat: " + e.getMessage());
            return false;
        }
    }

    // DELETE: Remove a threat
    public boolean deleteThreat(int threatId) {

        String sql = "DELETE FROM Threats WHERE threat_id=?";

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                return false;
            }

            try (PreparedStatement pst = con.prepareStatement(sql)) {

                pst.setInt(1, threatId);

                return pst.executeUpdate() > 0;
            }

        } catch (SQLException e) {

            System.out.println("Error Deleting Threat: " + e.getMessage());
            return false;
        }
    }
}