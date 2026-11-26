package dao;

import database.DatabaseConnection;
import model.ThreatEvent;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

public class ThreatEventDAO {

    // INSERT: Add a threat event
    public boolean addEvent(ThreatEvent event) {

        String sql = "INSERT INTO ThreatEvents "
                + "(threat_id, event_date, event_count) "
                + "VALUES (?, ?, ?)";

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                return false;
            }

            try (PreparedStatement pst = con.prepareStatement(sql)) {

                pst.setInt(1, event.getThreatId());
                pst.setString(2, event.getEventDate());
                pst.setInt(3, event.getEventCount());

                pst.executeUpdate();

                return true;
            }

        } catch (SQLException e) {

            System.out.println("Error Adding Event: " + e.getMessage());
            return false;
        }
    }

    // SELECT: Retrieve events for a particular threat
    public ArrayList<ThreatEvent> getEventsByThreat(int threatId) {

        ArrayList<ThreatEvent> events = new ArrayList<>();

        String sql = "SELECT * FROM ThreatEvents "
                + "WHERE threat_id = ? ORDER BY event_date ASC";

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                return events;
            }

            try (PreparedStatement pst = con.prepareStatement(sql)) {

                pst.setInt(1, threatId);

                try (ResultSet rs = pst.executeQuery()) {

                    while (rs.next()) {

                        ThreatEvent event = new ThreatEvent(
                                rs.getInt("event_id"),
                                rs.getInt("threat_id"),
                                rs.getString("event_date"),
                                rs.getInt("event_count")
                        );

                        events.add(event);
                    }
                }
            }

        } catch (SQLException e) {

            System.out.println("Error Retrieving Events: " + e.getMessage());
        }

        return events;
    }
}