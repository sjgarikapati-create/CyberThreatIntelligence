package gui;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import database.DatabaseConnection;

public class ThreatAnalysisFrame extends JFrame {

    private final JTable table;
    private final DefaultTableModel model;

    public ThreatAnalysisFrame() {

        setTitle("Threat Analysis");
        setSize(1000, 600);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout());

        JLabel heading = new JLabel("Threat Activity Analysis");
        heading.setFont(new Font("Arial", Font.BOLD, 25));
        heading.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        add(heading, BorderLayout.NORTH);

        String[] columns = {
            "Threat Name",
            "Category",
            "Severity",
            "Observations",
            "Average Activity",
            "Latest Activity",
            "Trend Status"
        };

        model = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        table = new JTable(model);
        table.setRowHeight(30);
        table.setFont(new Font("Arial", Font.PLAIN, 13));
        table.getTableHeader().setFont(new Font("Arial", Font.BOLD, 13));

        JScrollPane scrollPane = new JScrollPane(table);
        add(scrollPane, BorderLayout.CENTER);

        JButton refreshButton = new JButton("Refresh Analysis");
        refreshButton.addActionListener(e -> loadAnalysis());

        JPanel bottomPanel = new JPanel();
        bottomPanel.add(refreshButton);

        add(bottomPanel, BorderLayout.SOUTH);

        loadAnalysis();
    }

    private void loadAnalysis() {

        model.setRowCount(0);

        String sql =
            "SELECT t.threat_name, t.category, t.severity, " +
            "e.event_count, e.event_date " +
            "FROM Threats t " +
            "LEFT JOIN ThreatEvents e ON t.threat_id = e.threat_id " +
            "ORDER BY t.threat_id, e.event_date";

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                JOptionPane.showMessageDialog(
                    this, "Database connection failed!"
                );
                return;
            }

            try (Statement stmt = con.createStatement();
                 ResultSet rs = stmt.executeQuery(sql)) {

                String currentThreat = null;
                String category = "";
                String severity = "";

                List<Integer> counts = new ArrayList<>();

                while (rs.next()) {

                    String threatName = rs.getString("threat_name");

                    if (currentThreat != null &&
                        !currentThreat.equals(threatName)) {

                        addAnalysisRow(
                            currentThreat, category, severity, counts
                        );

                        counts.clear();
                    }

                    currentThreat = threatName;
                    category = rs.getString("category");
                    severity = rs.getString("severity");

                    int count = rs.getInt("event_count");

                    if (!rs.wasNull()) {
                        counts.add(count);
                    }
                }

                if (currentThreat != null) {
                    addAnalysisRow(
                        currentThreat, category, severity, counts
                    );
                }
            }

        } catch (SQLException e) {

            JOptionPane.showMessageDialog(
                this,
                "Error loading analysis: " + e.getMessage()
            );
        }
    }

    private void addAnalysisRow(
        String name,
        String category,
        String severity,
        List<Integer> counts
    ) {

        int observations = counts.size();
        double average = 0;
        int latest = 0;
        String trend = "Insufficient Data";

        if (observations > 0) {

            int total = 0;

            for (int count : counts) {
                total += count;
            }

            average = (double) total / observations;
            latest = counts.get(observations - 1);
        }

        if (observations >= 3) {

            int first = counts.get(0);
            int last = counts.get(observations - 1);

            if (last > first) {
                trend = "Increasing";
            } else if (last < first) {
                trend = "Decreasing";
            } else {
                trend = "Stable";
            }
        }

        model.addRow(new Object[]{
            name,
            category,
            severity,
            observations,
            String.format("%.2f", average),
            latest,
            trend
        });
    }
}