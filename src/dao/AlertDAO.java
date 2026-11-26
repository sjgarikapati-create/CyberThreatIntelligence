package dao;

import database.DatabaseConnection;
import model.ThreatAlert;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

public class AlertDAO {

    // INSERT: Add a new alert
    public boolean addAlert(ThreatAlert alert) {

        String sql = "INSERT INTO Alerts "
                + "(threat_id, alert_date, risk_level, message) "
                + "VALUES (?, ?, ?, ?)";

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                return false;
            }

            try (PreparedStatement pst = con.prepareStatement(sql)) {

                pst.setInt(1, alert.getThreatId());
                pst.setString(2, alert.getAlertDate());
                pst.setString(3, alert.getRiskLevel());
                pst.setString(4, alert.getMessage());

                pst.executeUpdate();

                return true;
            }

        } catch (SQLException e) {

            System.out.println("Error Adding Alert: " + e.getMessage());
            return false;
        }
    }

    // SELECT: Retrieve all alerts
    public ArrayList<ThreatAlert> getAllAlerts() {

        ArrayList<ThreatAlert> alerts = new ArrayList<>();

        String sql = "SELECT * FROM Alerts";

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                return alerts;
            }

            try (PreparedStatement pst = con.prepareStatement(sql);
                 ResultSet rs = pst.executeQuery()) {

                while (rs.next()) {

                    ThreatAlert alert = new ThreatAlert(
                            rs.getInt("alert_id"),
                            rs.getInt("threat_id"),
                            rs.getString("alert_date"),
                            rs.getString("risk_level"),
                            rs.getString("message")
                    );

                    alerts.add(alert);
                }
            }

        } catch (SQLException e) {

            System.out.println("Error Retrieving Alerts: " + e.getMessage());
        }

        return alerts;
    }
}