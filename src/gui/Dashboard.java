package gui;

import javax.swing.*;
import java.awt.*;
import java.util.List;

import dao.DashboardDAO;
import analysis.EmergingThreatDetector;
import analysis.EmergingThreatDetector.EmergingSignal;
import analysis.EmergingThreatFrame;
import charts.ThreatActivityChart;

public class Dashboard extends JFrame {

    private final DashboardDAO dao = new DashboardDAO();

    public Dashboard() {

        setTitle("Cyber Threat Intelligence Dashboard");
        setSize(1200, 750);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());

        // =====================================
        // SIDEBAR
        // =====================================

        JPanel sidebar = new JPanel();

        sidebar.setPreferredSize(new Dimension(240, 750));
        sidebar.setBackground(new Color(15, 23, 42));
        sidebar.setLayout(new GridLayout(13, 1, 5, 5));

        JLabel logo = new JLabel("  CYBER INTELLIGENCE");

        logo.setForeground(Color.WHITE);
        logo.setFont(new Font("Arial", Font.BOLD, 17));

        sidebar.add(logo);

        String[] menuItems = {
            "Dashboard",
            "Live Threat Intelligence",
            "CISA Analysis",
            "Threat Analysis",
            "Emerging Threats",
            "Security Alerts",
            "Forecasting",
            "Dataset Management",
            "Ground Truth",
            "Evaluation",
            "Charts",
            "Logout"
        };

        for (String item : menuItems) {

            JButton button = new JButton(item);

            button.setForeground(Color.WHITE);
            button.setBackground(new Color(30, 41, 59));
            button.setFocusPainted(false);

            sidebar.add(button);

            if (item.equals("Live Threat Intelligence")) {
                button.addActionListener(e ->
                    new CISADataFrame().setVisible(true)
                );
            }

            if (item.equals("CISA Analysis")) {
                button.addActionListener(e ->
                    new CISAAnalysisFrame().setVisible(true)
                );
            }

            if (item.equals("Threat Analysis")) {
                button.addActionListener(e ->
                    new ThreatAnalysisFrame().setVisible(true)
                );
            }

            if (item.equals("Emerging Threats")) {
                button.addActionListener(e ->
                    new EmergingThreatFrame().setVisible(true)
                );
            }

            if (item.equals("Security Alerts")) {
                button.addActionListener(e ->
                    new SecurityAlertsFrame().setVisible(true)
                );
            }

            if (item.equals("Forecasting")) {
                button.addActionListener(e ->
                    new ForecastingFrame().setVisible(true)
                );
            }

            if (item.equals("Dataset Management")) {
                button.addActionListener(e ->
                    new DatasetImportFrame().setVisible(true)
                );
            }

            if (item.equals("Ground Truth")) {
                button.addActionListener(e ->
                    new GroundTruthFrame().setVisible(true)
                );
            }

            if (item.equals("Evaluation")) {
                button.addActionListener(e ->
                    new EvaluationFrame().setVisible(true)
                );
            }

            if (item.equals("Charts")) {
                button.addActionListener(e ->
                    new ThreatActivityChart().setVisible(true)
                );
            }

            if (item.equals("Logout")) {
                button.addActionListener(e -> {
                    new LoginFrame().setVisible(true);
                    dispose();
                });
            }
        }

        // =====================================
        // MAIN DASHBOARD
        // =====================================

        JPanel content = new JPanel(new BorderLayout());

        content.setBackground(new Color(241, 245, 249));

        JPanel header = new JPanel(new BorderLayout());

        header.setBackground(Color.WHITE);
        header.setPreferredSize(new Dimension(900, 80));

        JLabel heading = new JLabel(
            "  Live Cyber Threat Intelligence Dashboard"
        );

        heading.setFont(new Font("Arial", Font.BOLD, 23));

        header.add(heading, BorderLayout.CENTER);

        content.add(header, BorderLayout.NORTH);

        // =====================================
        // LIVE STATISTICS
        // =====================================

        JPanel statistics = new JPanel(
                new GridLayout(2, 3, 20, 20)
        );

        statistics.setBackground(new Color(241, 245, 249));

        statistics.setBorder(
            BorderFactory.createEmptyBorder(30, 30, 30, 30)
        );

        addCard(
            statistics,
            "TOTAL CISA VULNERABILITIES",
            String.valueOf(dao.getTotalCISAVulnerabilities())
        );

        addCard(
            statistics,
            "RANSOMWARE-ASSOCIATED",
            String.valueOf(dao.getRansomwareVulnerabilities())
        );

        addCard(
            statistics,
            "AFFECTED VENDORS",
            String.valueOf(dao.getTotalCISAVendors())
        );

        addCard(
            statistics,
            "LATEST DATE ADDITIONS",
            String.valueOf(dao.getLatestCISAAdditions())
        );

        addCard(
            statistics,
            "LATEST CATALOGUE DATE",
            dao.getLatestCISAAdditionDate()
        );

        addCard(
            statistics,
            "LATEST EMERGING SIGNAL",
            getLatestEmergingStatus()
        );

        content.add(statistics, BorderLayout.CENTER);

        // =====================================
        // DATA SOURCE FOOTER
        // =====================================

        JLabel footer = new JLabel(
            "Data Source: CISA Known Exploited Vulnerabilities Catalogue",
            SwingConstants.CENTER
        );

        footer.setFont(new Font("Arial", Font.PLAIN, 13));

        content.add(footer, BorderLayout.SOUTH);

        add(sidebar, BorderLayout.WEST);
        add(content, BorderLayout.CENTER);
    }

    // =====================================
    // LATEST EMERGING SIGNAL
    // =====================================

    private String getLatestEmergingStatus() {

        try {

            EmergingThreatDetector detector =
                    new EmergingThreatDetector();

            List<EmergingSignal> signals =
                    detector.detectCISAEmergingSignals();

            if (signals.isEmpty()) {
                return "Insufficient Data";
            }

            EmergingSignal latest =
                    signals.get(signals.size() - 1);

            if (latest.getStatus().equals("EMERGING")) {
                return "EMERGING";
            }

            return "NORMAL";

        } catch (Exception e) {

            System.out.println(
                    "Emerging signal error: " + e.getMessage()
            );

            return "Unavailable";
        }
    }

    // =====================================
    // DASHBOARD CARD
    // =====================================

    private void addCard(
        JPanel panel,
        String title,
        String value
    ) {

        JPanel card = new JPanel(new GridLayout(2, 1));

        card.setBackground(Color.WHITE);

        JLabel titleLabel = new JLabel(
            title,
            SwingConstants.CENTER
        );

        titleLabel.setFont(
            new Font("Arial", Font.BOLD, 14)
        );

        titleLabel.setForeground(
            new Color(71, 85, 105)
        );

        JLabel valueLabel = new JLabel(
            value,
            SwingConstants.CENTER
        );

        valueLabel.setFont(
            new Font("Arial", Font.BOLD, 25)
        );

        valueLabel.setForeground(
            new Color(37, 99, 235)
        );

        card.add(titleLabel);
        card.add(valueLabel);

        panel.add(card);
    }
}