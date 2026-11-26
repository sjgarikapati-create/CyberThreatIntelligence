package gui;

import database.DatabaseConnection;
import utilities.CISADataFetcher;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.sql.*;
import java.util.concurrent.ExecutionException;

public class CISADataFrame extends JFrame {

    private final JTable vulnerabilityTable;
    private final DefaultTableModel tableModel;
    private final JLabel totalLabel;
    private final JButton fetchButton;

    public CISADataFrame() {

        setTitle("Live Cyber Threat Intelligence");
        setSize(1250, 750);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(10, 10));

        JLabel heading = new JLabel(
            "LIVE CISA THREAT INTELLIGENCE",
            SwingConstants.CENTER
        );

        heading.setFont(new Font("Arial", Font.BOLD, 25));
        heading.setBorder(
            BorderFactory.createEmptyBorder(20, 10, 15, 10)
        );

        add(heading, BorderLayout.NORTH);

        String[] columns = {
            "CVE ID",
            "Vendor",
            "Product",
            "Vulnerability Name",
            "Date Added",
            "Ransomware Use"
        };

        tableModel = new DefaultTableModel(columns, 0) {

            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        vulnerabilityTable = new JTable(tableModel);
        vulnerabilityTable.setRowHeight(27);
        vulnerabilityTable.setAutoResizeMode(
            JTable.AUTO_RESIZE_OFF
        );

        vulnerabilityTable.getColumnModel()
                .getColumn(0).setPreferredWidth(140);

        vulnerabilityTable.getColumnModel()
                .getColumn(1).setPreferredWidth(150);

        vulnerabilityTable.getColumnModel()
                .getColumn(2).setPreferredWidth(150);

        vulnerabilityTable.getColumnModel()
                .getColumn(3).setPreferredWidth(400);

        vulnerabilityTable.getColumnModel()
                .getColumn(4).setPreferredWidth(120);

        vulnerabilityTable.getColumnModel()
                .getColumn(5).setPreferredWidth(150);

        JScrollPane scrollPane =
            new JScrollPane(vulnerabilityTable);

        add(scrollPane, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(
            new FlowLayout(FlowLayout.CENTER, 20, 15)
        );

        totalLabel = new JLabel("Total Vulnerabilities: 0");
        totalLabel.setFont(
            new Font("Arial", Font.BOLD, 16)
        );

        JButton refreshButton = new JButton("Refresh Data");

        refreshButton.addActionListener(
            e -> loadVulnerabilities()
        );

        fetchButton = new JButton("Fetch Latest Data");

        fetchButton.addActionListener(
            e -> fetchLatestData()
        );

        bottomPanel.add(totalLabel);
        bottomPanel.add(refreshButton);
        bottomPanel.add(fetchButton);

        add(bottomPanel, BorderLayout.SOUTH);

        loadVulnerabilities();
    }

    private void loadVulnerabilities() {

        tableModel.setRowCount(0);

        String sql = """
            SELECT cve_id,
                   vendor,
                   product,
                   vulnerability_name,
                   date_added,
                   ransomware_use
            FROM CISAVulnerabilities
            ORDER BY date_added DESC
            """;

        try (Connection con =
                DatabaseConnection.getConnection()) {

            if (con == null) {
                throw new SQLException(
                    "Database connection failed."
                );
            }

            try (PreparedStatement pst =
                    con.prepareStatement(sql);
                 ResultSet rs = pst.executeQuery()) {

                int count = 0;

                while (rs.next()) {

                    Object[] row = {
                        rs.getString("cve_id"),
                        rs.getString("vendor"),
                        rs.getString("product"),
                        rs.getString("vulnerability_name"),
                        rs.getString("date_added"),
                        rs.getString("ransomware_use")
                    };

                    tableModel.addRow(row);
                    count++;
                }

                totalLabel.setText(
                    "Total Vulnerabilities: " + count
                );
            }

        } catch (SQLException e) {

            JOptionPane.showMessageDialog(
                this,
                "Unable to load vulnerabilities: "
                + e.getMessage(),
                "Database Error",
                JOptionPane.ERROR_MESSAGE
            );
        }
    }

    private void fetchLatestData() {

        fetchButton.setEnabled(false);
        fetchButton.setText("Fetching...");

        SwingWorker<Integer, Void> worker;
        worker = new SwingWorker<>() {
            
            @Override
            protected Integer doInBackground() throws Exception {

                CISADataFetcher fetcher =
                        new CISADataFetcher();
                
                return fetcher.fetchAndSaveData();
            }

            @Override
            protected void done() {

                fetchButton.setEnabled(true);
                fetchButton.setText("Fetch Latest Data");

                try {

                    int count = get();

                    loadVulnerabilities();

                    JOptionPane.showMessageDialog(
                            CISADataFrame.this,
                            """
                            CISA data updated successfully!
                            Records processed: """ + count,
                            "Update Successful",
                            JOptionPane.INFORMATION_MESSAGE
                    );

                } catch (HeadlessException | InterruptedException | ExecutionException e) {

                    JOptionPane.showMessageDialog(
                            CISADataFrame.this,
                            "Unable to fetch live CISA data:\n"
                                    + e.getMessage(),
                            "Fetch Failed",
                            JOptionPane.ERROR_MESSAGE
                    );
                }
            }
        };

        worker.execute();
    }
}