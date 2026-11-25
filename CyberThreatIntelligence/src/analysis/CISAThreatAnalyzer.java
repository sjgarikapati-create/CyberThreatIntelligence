package analysis;

import database.DatabaseConnection;
import java.sql.*;

public class CISAThreatAnalyzer {

    // 1. Get total vulnerabilities
    public int getTotalVulnerabilities() {

        String sql =
            "SELECT COUNT(*) FROM CISAVulnerabilities";

        return getCount(sql);
    }

    // 2. Get ransomware-associated vulnerabilities
    public int getRansomwareVulnerabilities() {

        String sql =
            "SELECT COUNT(*) FROM CISAVulnerabilities " +
            "WHERE LOWER(ransomware_use) = 'known'";

        return getCount(sql);
    }

    // 3. Get the top 10 affected vendors
    public ResultSet getTopVendors(Connection con)
            throws SQLException {

        String sql = """
            SELECT vendor, COUNT(*) AS total
            FROM CISAVulnerabilities
            GROUP BY vendor
            ORDER BY total DESC
            LIMIT 10
            """;

        Statement stmt = con.createStatement();

        return stmt.executeQuery(sql);
    }

    // 4. Get vulnerabilities added per week
    public ResultSet getWeeklyVulnerabilities(Connection con)
            throws SQLException {

        String sql = """
            SELECT strftime('%Y-W%W', date_added) AS week,
                   COUNT(*) AS total
            FROM CISAVulnerabilities
            GROUP BY week
            ORDER BY week
            """;

        Statement stmt = con.createStatement();

        return stmt.executeQuery(sql);
    }

    // Helper method for counting records
    private int getCount(String sql) {

        try (Connection con =
                DatabaseConnection.getConnection();
             Statement stmt = con.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next()) {
                return rs.getInt(1);
            }

        } catch (SQLException e) {

            System.out.println(
                "Analysis Error: " + e.getMessage()
            );
        }

        return 0;
    }
}