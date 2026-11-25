package processing;

import database.DatabaseConnection;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class CISADataProcessor {

    // Stores weekly observations
    public static class WeeklyObservation {

        private final String week;
        private final int count;

        public WeeklyObservation(String week, int count) {
            this.week = week;
            this.count = count;
        }

        public String getWeek() {
            return week;
        }

        public int getCount() {
            return count;
        }
    }

    // Stores vendor information
    public static class VendorSummary {

        private final String vendor;
        private final int count;

        public VendorSummary(String vendor, int count) {
            this.vendor = vendor;
            this.count = count;
        }

        public String getVendor() {
            return vendor;
        }

        public int getCount() {
            return count;
        }
    }

    // Gets total vulnerabilities
    public int getTotalVulnerabilities() throws SQLException {

        String sql = "SELECT COUNT(*) FROM CISAVulnerabilities";

        return getCount(sql);
    }

    // Gets ransomware-associated vulnerabilities
    public int getRansomwareVulnerabilities() throws SQLException {

        String sql = """
            SELECT COUNT(*)
            FROM CISAVulnerabilities
            WHERE LOWER(ransomware_use) = 'known'
            """;

        return getCount(sql);
    }

    // Gets the top 10 affected vendors
    public List<VendorSummary> getTopVendors() throws SQLException {

        List<VendorSummary> vendors = new ArrayList<>();

        String sql = """
            SELECT vendor, COUNT(*) AS total
            FROM CISAVulnerabilities
            GROUP BY vendor
            ORDER BY total DESC
            LIMIT 10
            """;

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                throw new SQLException("Database connection failed.");
            }

            try (PreparedStatement pst = con.prepareStatement(sql);
                 ResultSet rs = pst.executeQuery()) {

                while (rs.next()) {

                    vendors.add(
                        new VendorSummary(
                            rs.getString("vendor"),
                            rs.getInt("total")
                        )
                    );
                }
            }
        }

        return vendors;
    }

    // Gets all weekly observations, including weeks with zero additions
    public List<WeeklyObservation> getAllWeeklyObservations()
            throws SQLException {

        Map<LocalDate, Integer> weeklyCounts = new TreeMap<>();

        String sql = """
            SELECT
                date(
                    date_added,
                    '-' ||
                    ((CAST(strftime('%w', date_added) AS INTEGER) + 6) % 7)
                    || ' days'
                ) AS week_start,
                COUNT(*) AS total
            FROM CISAVulnerabilities
            WHERE date_added IS NOT NULL
              AND date(date_added) IS NOT NULL
            GROUP BY week_start
            ORDER BY week_start
            """;

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                throw new SQLException("Database connection failed.");
            }

            try (PreparedStatement pst = con.prepareStatement(sql);
                 ResultSet rs = pst.executeQuery()) {

                while (rs.next()) {

                    String weekStart = rs.getString("week_start");

                    if (weekStart != null) {

                        LocalDate date = LocalDate.parse(weekStart);

                        weeklyCounts.put(
                            date,
                            rs.getInt("total")
                        );
                    }
                }
            }
        }

        List<WeeklyObservation> observations = new ArrayList<>();

        if (weeklyCounts.isEmpty()) {
            return observations;
        }

        LocalDate currentWeek = weeklyCounts.keySet()
                .iterator().next();

        LocalDate lastWeek = null;

        for (LocalDate date : weeklyCounts.keySet()) {
            lastWeek = date;
        }

        while (!currentWeek.isAfter(lastWeek)) {

            int count = weeklyCounts.getOrDefault(
                    currentWeek, 0
            );

            observations.add(
                new WeeklyObservation(
                    currentWeek.toString(),
                    count
                )
            );

            currentWeek = currentWeek.plusWeeks(1);
        }

        return observations;
    }

    // Gets the latest specified number of continuous weeks
    public List<WeeklyObservation> getLatestWeeklyObservations(int weeks)
            throws SQLException {

        if (weeks <= 0) {
            throw new IllegalArgumentException(
                "Number of weeks must be positive."
            );
        }

        List<WeeklyObservation> allObservations =
                getAllWeeklyObservations();

        int start = Math.max(
                0,
                allObservations.size() - weeks
        );

        return new ArrayList<>(
                allObservations.subList(
                    start,
                    allObservations.size()
                )
        );
    }

    // Counts all weekly periods, including zero-addition weeks
    public int getTotalObservations() throws SQLException {

        return getAllWeeklyObservations().size();
    }

    // Reusable database counting method
    private int getCount(String sql) throws SQLException {

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                throw new SQLException("Database connection failed.");
            }

            try (PreparedStatement pst = con.prepareStatement(sql);
                 ResultSet rs = pst.executeQuery()) {

                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        }

        return 0;
    }
}