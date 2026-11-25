package analysis;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.sql.SQLException;
import java.util.List;

public class EmergingThreatFrame extends JFrame {

    private final DefaultTableModel model;
    private final JLabel summaryLabel;

    private final EmergingThreatDetector detector =
            new EmergingThreatDetector();

    public EmergingThreatFrame() {

        setTitle("Live CISA Emerging Threat Detection");
        setSize(1100, 600);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(10, 10));

        JLabel heading = new JLabel(
                "LIVE CISA EMERGING THREAT DETECTION",
                SwingConstants.CENTER
        );

        heading.setFont(new Font("Arial", Font.BOLD, 23));
        heading.setBorder(
                BorderFactory.createEmptyBorder(20, 10, 15, 10)
        );

        add(heading, BorderLayout.NORTH);

        String[] columns = {
            "Week",
            "Historical Average",
            "Recent Average",
            "Growth Rate (%)",
            "Detection Status"
        };

        model = new DefaultTableModel(columns, 0) {

            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        JTable table = new JTable(model);
        table.setRowHeight(30);

        add(new JScrollPane(table), BorderLayout.CENTER);

        summaryLabel = new JLabel(
                "Loading CISA data...",
                SwingConstants.CENTER
        );

        JButton refreshButton =
                new JButton("Refresh Detection");

        refreshButton.addActionListener(
                e -> detectThreats()
        );

        JPanel bottomPanel = new JPanel(new BorderLayout());

        bottomPanel.add(summaryLabel, BorderLayout.NORTH);
        bottomPanel.add(refreshButton, BorderLayout.SOUTH);

        bottomPanel.setBorder(
                BorderFactory.createEmptyBorder(10, 15, 15, 15)
        );

        add(bottomPanel, BorderLayout.SOUTH);

        detectThreats();
    }

    private void detectThreats() {

        model.setRowCount(0);
        summaryLabel.setText("Analysing live CISA data...");

        try {

            List<EmergingThreatDetector.EmergingSignal> signals =
                    detector.detectCISAEmergingSignals();

            int emergingCount = 0;

            for (EmergingThreatDetector.EmergingSignal signal
                    : signals) {

                String growth;

                if (Double.isInfinite(signal.getGrowthRate())) {
                    growth = "N/A (Zero baseline)";
                } else {
                    growth = String.format(
                            "%.2f",
                            signal.getGrowthRate()
                    );
                }

                model.addRow(new Object[]{
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
                    signal.getStatus()
                });

                if (signal.getStatus().equals("EMERGING")) {
                    emergingCount++;
                }
            }

            summaryLabel.setText(
                    "Weeks analysed: " + signals.size()
                    + " | Emerging signals detected: "
                    + emergingCount
            );

            if (signals.isEmpty()) {
                summaryLabel.setText(
                        "Insufficient CISA weekly observations."
                );
            }

        } catch (SQLException e) {

            JOptionPane.showMessageDialog(
                    this,
                    "Unable to analyse CISA data:\n"
                    + e.getMessage(),
                    "Analysis Error",
                    JOptionPane.ERROR_MESSAGE
            );

            summaryLabel.setText("Analysis failed.");
        }
    }

    public static void main(String[] args) {

        SwingUtilities.invokeLater(() -> {
            new EmergingThreatFrame().setVisible(true);
        });
    }
}