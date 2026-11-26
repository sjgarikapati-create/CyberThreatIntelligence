package analysis;

import database.DatabaseConnection;
import java.sql.Connection;
import java.sql.ResultSet;

public class CISAAnalysisTest {

    public static void main(String[] args) {

        CISAThreatAnalyzer analyzer =
                new CISAThreatAnalyzer();

        System.out.println("===== LIVE CISA DATA ANALYSIS =====");

        System.out.println(
            "Total Vulnerabilities: "
            + analyzer.getTotalVulnerabilities()
        );

        System.out.println(
            "Ransomware-Associated Vulnerabilities: "
            + analyzer.getRansomwareVulnerabilities()
        );

        try (Connection con =
                DatabaseConnection.getConnection()) {

            System.out.println("\n===== TOP 10 VENDORS =====");

            try (ResultSet rs = analyzer.getTopVendors(con)) {

                while (rs.next()) {
                    System.out.println(
                        rs.getString("vendor")
                        + " : "
                        + rs.getInt("total")
                    );
                }
            }

            System.out.println("\n===== WEEKLY CATALOGUE ADDITIONS =====");

            try (ResultSet rs =
                    analyzer.getWeeklyVulnerabilities(con)) {

                while (rs.next()) {
                    System.out.println(
                        rs.getString("week")
                        + " : "
                        + rs.getInt("total")
                    );
                }
            }

        } catch (Exception e) {
            System.out.println("Analysis failed: " + e.getMessage());
        }
    }
}