package gui;

import analysis.EmergingThreatDetector;
import analysis.EmergingThreatDetector.EmergingSignal;
import database.DatabaseConnection;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.sql.*;
import java.util.List;

public class SecurityAlertsFrame extends JFrame {

    private final DefaultTableModel syntheticModel;
    private final DefaultTableModel cisaModel;

    private final JLabel summaryLabel;

    private final EmergingThreatDetector detector =
            new EmergingThreatDetector();

    public SecurityAlertsFrame() {

        setTitle("Cyber Security Alerts");
        setSize(1150, 680);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout());

        JLabel heading = new JLabel(
                "CYBER SECURITY ALERTS",
                SwingConstants.CENTER
        );

        heading.setFont(new Font("Arial", Font.BOLD, 24));
        heading.setBorder(
                BorderFactory.createEmptyBorder(20, 10, 15, 10)
        );

        add(heading, BorderLayout.NORTH);

        JTabbedPane tabs = new JTabbedPane();

        // Synthetic alerts
        syntheticModel = new DefaultTableModel(
                new String[]{
                    "Alert ID",
                    "Threat Name",
                    "Alert Date",
                    "Risk Level",
                    "Alert Message"
                }, 0
        ) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        JTable syntheticTable = new JTable(syntheticModel);
        syntheticTable.setRowHeight(30);

        tabs.addTab(
                "Existing Security Alerts",
                new JScrollPane(syntheticTable)
        );

        // Live CISA signals
        cisaModel = new DefaultTableModel(
                new String[]{
                    "Week",
                    "Historical Average",
                    "Recent Average",
                    "Growth Rate (%)",
                    "Detection Status",
                    "Signal Scope"
                }, 0
        ) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        JTable cisaTable = new JTable(cisaModel);
        cisaTable.setRowHeight(30);

        tabs.addTab(
                "Live CISA Signals",
                new JScrollPane(cisaTable)
        );

        add(tabs, BorderLayout.CENTER);

        summaryLabel = new JLabel(
                "Loading alert information...",
                SwingConstants.CENTER
        );

        JButton refreshButton =
                new JButton("Refresh Alerts");

        refreshButton.addActionListener(e -> refreshAlerts());

        JPanel bottomPanel = new JPanel(new BorderLayout());

        bottomPanel.add(summaryLabel, BorderLayout.NORTH);
        bottomPanel.add(refreshButton, BorderLayout.SOUTH);

        bottomPanel.setBorder(
                BorderFactory.createEmptyBorder(10, 15, 15, 15)
        );

        add(bottomPanel, BorderLayout.SOUTH);

        refreshAlerts();
    }

    // =========================================
    // REFRESH BOTH ALERT SECTIONS
    // =========================================

    private void refreshAlerts() {

        loadSyntheticAlerts();
        loadCISAAlerts();
    }

    // =========================================
    // LOAD SYNTHETIC ALERTS
    // =========================================

    private void loadSyntheticAlerts() {

        syntheticModel.setRowCount(0);

        String sql = """
            SELECT a.alert_id,
                   t.threat_name,
                   a.alert_date,
                   a.risk_level,
                   a.message
            FROM Alerts a
            LEFT JOIN Threats t
            ON a.threat_id = t.threat_id
            ORDER BY a.alert_id DESC
            """;

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                throw new SQLException("Database connection failed.");
            }

            try (PreparedStatement pst = con.prepareStatement(sql);
                 ResultSet rs = pst.executeQuery()) {

                while (rs.next()) {

                    syntheticModel.addRow(new Object[]{
                        rs.getInt("alert_id"),
                        rs.getString("threat_name"),
                        rs.getString("alert_date"),
                        rs.getString("risk_level"),
                        rs.getString("message")
                    });
                }
            }

        } catch (SQLException e) {

            showError("Unable to load existing alerts", e);
        }
    }

    // =========================================
    // LOAD LIVE CISA SIGNALS
    // =========================================

    private void loadCISAAlerts() {

        cisaModel.setRowCount(0);

        try {

            List<EmergingSignal> signals =
                    detector.detectCISAEmergingSignals();

            if (signals.isEmpty()) {

                summaryLabel.setText(
                        "Insufficient historical observations for CISA detection."
                );

                return;
            }

            int historicalEmergingCount = 0;

            EmergingSignal latestSignal =
                    signals.get(signals.size() - 1);

            for (int i = 0; i < signals.size(); i++) {

                EmergingSignal signal = signals.get(i);

                boolean isLatest =
                        i == signals.size() - 1;

                if (signal.getStatus().equals("EMERGING")) {
                    historicalEmergingCount++;
                }

                String growth;

                if (Double.isInfinite(signal.getGrowthRate())) {
                    growth = "N/A";
                } else {
                    growth = String.format(
                            "%.2f",
                            signal.getGrowthRate()
                    );
                }

                String scope = isLatest
                        ? "LATEST OBSERVED WEEK"
                        : "HISTORICAL SIGNAL";

                cisaModel.addRow(new Object[]{
                    signal.getWeek(),

                    String.format(
                            "%.2f",
                            signal.getHistoricalAverage()
                    ),

                    String.format(
                            "%.2f",
                            signal.getRecentAverage()
                    ),

                    growth,

                    signal.getStatus(),

                    scope
                });
            }

            String latestStatus =
                    latestSignal.getStatus();

            String latestDescription =
                    latestStatus.equals("EMERGING")
                    ? "Emerging catalogue-addition signal"
                    : "No emerging catalogue-addition signal";

            summaryLabel.setText(
                    "Historical emerging signals: "
                    + historicalEmergingCount
                    + " | Latest observed week: "
                    + latestSignal.getWeek()
                    + " | Latest status: "
                    + latestDescription
            );

        } catch (SQLException e) {

            showError("Unable to load live CISA signals", e);
        }
    }

    // =========================================
    // ERROR HANDLING
    // =========================================

    private void showError(
            String message,
            SQLException e) {

        JOptionPane.showMessageDialog(
                this,
                message + ":\n" + e.getMessage(),
                "Database Error",
                JOptionPane.ERROR_MESSAGE
        );
    }

    public static void main(String[] args) {

        SwingUtilities.invokeLater(() ->
                new SecurityAlertsFrame().setVisible(true)
        );
    }
}