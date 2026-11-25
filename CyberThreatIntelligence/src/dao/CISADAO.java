package dao;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import database.DatabaseConnection;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CISADAO {

    public void createTable() {

        String sql = """
            CREATE TABLE IF NOT EXISTS CISAVulnerabilities (
                cve_id TEXT PRIMARY KEY,
                vendor TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                description TEXT,
                required_action TEXT,
                due_date TEXT,
                ransomware_use TEXT
            )
            """;

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                throw new SQLException("Database connection failed.");
            }

            try (PreparedStatement pst = con.prepareStatement(sql)) {
                pst.execute();
                System.out.println("CISA Vulnerabilities Table Created!");
            }

        } catch (SQLException e) {
            System.out.println("CISA Table Error: " + e.getMessage());
        }
    }

    public int saveVulnerabilities(JsonArray vulnerabilities) {

        String sql = """
            INSERT INTO CISAVulnerabilities
            (cve_id, vendor, product, vulnerability_name,
             date_added, description, required_action,
             due_date, ransomware_use)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)

            ON CONFLICT(cve_id) DO UPDATE SET
                vendor = excluded.vendor,
                product = excluded.product,
                vulnerability_name = excluded.vulnerability_name,
                date_added = excluded.date_added,
                description = excluded.description,
                required_action = excluded.required_action,
                due_date = excluded.due_date,
                ransomware_use = excluded.ransomware_use
            """;

        int savedCount = 0;

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                throw new SQLException("Database connection failed.");
            }

            con.setAutoCommit(false);

            try (PreparedStatement pst = con.prepareStatement(sql)) {

                for (JsonElement element : vulnerabilities) {

                    JsonObject vulnerability = element.getAsJsonObject();

                    pst.setString(1, getValue(vulnerability, "cveID"));
                    pst.setString(2, getValue(vulnerability, "vendorProject"));
                    pst.setString(3, getValue(vulnerability, "product"));
                    pst.setString(4, getValue(vulnerability, "vulnerabilityName"));
                    pst.setString(5, getValue(vulnerability, "dateAdded"));
                    pst.setString(6, getValue(vulnerability, "shortDescription"));
                    pst.setString(7, getValue(vulnerability, "requiredAction"));
                    pst.setString(8, getValue(vulnerability, "dueDate"));
                    pst.setString(9, getValue(vulnerability, "knownRansomwareCampaignUse"));

                    pst.addBatch();
                }

                pst.executeBatch();
                con.commit();

                savedCount = vulnerabilities.size();

            } catch (Exception e) {

                con.rollback();
                throw e;

            } finally {
                con.setAutoCommit(true);
            }

        } catch (Exception e) {

            System.out.println("CISA Data Saving Failed!");
            System.out.println(e.getMessage());
        }

        return savedCount;
    }

    private String getValue(JsonObject object, String key) {

        JsonElement element = object.get(key);

        if (element == null || element.isJsonNull()) {
            return "";
        }

        return element.getAsString();
    }
}