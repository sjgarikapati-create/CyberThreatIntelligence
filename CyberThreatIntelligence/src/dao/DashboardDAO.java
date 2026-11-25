package dao;

import database.DatabaseConnection;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class DashboardDAO {

    // Synthetic statistics

    public int getTotalThreats() {
        return getCount("SELECT COUNT(*) FROM Threats");
    }

    public int getTotalAlerts() {
        return getCount("SELECT COUNT(*) FROM Alerts");
    }

    public int getCriticalThreats() {
        return getCount(
                "SELECT COUNT(*) FROM Threats WHERE severity='Critical'"
        );
    }

    public int getEmergingThreats() {
        return getCount(
                "SELECT COUNT(*) FROM Alerts WHERE risk_level='EMERGING'"
        );
    }

    // Live CISA statistics

    public int getTotalCISAVulnerabilities() {
        return getCount(
                "SELECT COUNT(*) FROM CISAVulnerabilities"
        );
    }

    public int getRansomwareVulnerabilities() {
        return getCount(
                "SELECT COUNT(*) FROM CISAVulnerabilities " +
                "WHERE LOWER(ransomware_use)='known'"
        );
    }

    public int getTotalCISAVendors() {
        return getCount(
                "SELECT COUNT(DISTINCT vendor) " +
                "FROM CISAVulnerabilities"
        );
    }

    public int getLatestCISAAdditions() {
        return getCount("""
            SELECT COUNT(*)
            FROM CISAVulnerabilities
            WHERE date_added = (
                SELECT MAX(date_added)
                FROM CISAVulnerabilities
            )
            """);
    }

    public String getLatestCISAAdditionDate() {

        String sql =
                "SELECT MAX(date_added) FROM CISAVulnerabilities";

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                return "Unavailable";
            }

            try (PreparedStatement pst = con.prepareStatement(sql);
                 ResultSet rs = pst.executeQuery()) {

                if (rs.next()) {
                    String date = rs.getString(1);
                    return date == null ? "No Data" : date;
                }
            }

        } catch (Exception e) {
            System.out.println("Dashboard Error: " + e.getMessage());
        }

        return "Unavailable";
    }

    // Reusable counting method

    private int getCount(String sql) {

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                return 0;
            }

            try (PreparedStatement pst = con.prepareStatement(sql);
                 ResultSet rs = pst.executeQuery()) {

                if (rs.next()) {
                    return rs.getInt(1);
                }
            }

        } catch (Exception e) {
            System.out.println("Dashboard Error: " + e.getMessage());
        }

        return 0;
    }
}