package gui;

import database.DatabaseConnection;
import utilities.CISADataFetcher;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.sql.*;

public class DatasetImportFrame extends JFrame {

    private JTable table;
    private DefaultTableModel model;
    private File selectedFile;

    private JTable cisaTable;
    private DefaultTableModel cisaModel;

    private JLabel cisaStatusLabel;

    public DatasetImportFrame() {

        setTitle("Cyber Threat Intelligence - Dataset Management");
        setSize(1100, 700);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout());

        JLabel heading = new JLabel(
                "DATASET MANAGEMENT",
                SwingConstants.CENTER
        );

        heading.setFont(new Font("Arial", Font.BOLD, 24));
        heading.setForeground(Color.WHITE);
        heading.setOpaque(true);
        heading.setBackground(new Color(15, 23, 42));
        heading.setPreferredSize(new Dimension(1100, 50));

        add(heading, BorderLayout.NORTH);

        JTabbedPane tabs = new JTabbedPane();

        tabs.addTab("CSV Dataset Import", createCSVPanel());
        tabs.addTab("Live CISA Dataset", createCISAPanel());

        add(tabs, BorderLayout.CENTER);
    }

    // ==========================================
    // CSV DATASET IMPORT
    // ==========================================

    private JPanel createCSVPanel() {

        JPanel panel = new JPanel(new BorderLayout());

        JButton browseButton = new JButton("Browse CSV");
        JLabel fileLabel = new JLabel("No file selected");

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        topPanel.add(browseButton);
        topPanel.add(fileLabel);

        String[] columns = {
            "Threat Name",
            "Category",
            "Severity",
            "Description",
            "Event Date",
            "Event Count"
        };

        model = new DefaultTableModel(columns, 0) {

            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        table = new JTable(model);
        table.setRowHeight(25);

        JButton importButton = new JButton("Import Dataset");
        JButton clearButton = new JButton("Clear");

        JPanel bottomPanel = new JPanel();

        bottomPanel.add(importButton);
        bottomPanel.add(clearButton);

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        panel.add(bottomPanel, BorderLayout.SOUTH);

        browseButton.addActionListener(e -> chooseFile(fileLabel));

        importButton.addActionListener(e -> importDataset());

        clearButton.addActionListener(e -> clearData());

        return panel;
    }

    private void chooseFile(JLabel fileLabel) {

        JFileChooser chooser = new JFileChooser();

        int result = chooser.showOpenDialog(this);

        if (result == JFileChooser.APPROVE_OPTION) {

            selectedFile = chooser.getSelectedFile();

            fileLabel.setText(selectedFile.getName());

            loadCSV();
        }
    }

    private void loadCSV() {

        model.setRowCount(0);

        try (BufferedReader reader =
                new BufferedReader(new FileReader(selectedFile))) {

            String line;

            reader.readLine();

            while ((line = reader.readLine()) != null) {

                String[] values = parseCSVLine(line);

                if (values.length != 6) {
                    throw new IOException(
                            "Invalid CSV row: " + line
                    );
                }

                model.addRow(values);
            }

            JOptionPane.showMessageDialog(
                    this,
                    "CSV loaded successfully!\n"
                    + model.getRowCount() + " records found."
            );

        } catch (Exception e) {

            JOptionPane.showMessageDialog(
                    this,
                    "Error loading CSV: " + e.getMessage()
            );
        }
    }

    private void importDataset() {

        if (model.getRowCount() == 0) {

            JOptionPane.showMessageDialog(
                    this,
                    "Please select a CSV file first!"
            );

            return;
        }

        String findThreatSQL =
                "SELECT threat_id FROM Threats WHERE threat_name = ?";

        String insertThreatSQL =
                "INSERT INTO Threats "
                + "(threat_name, category, severity, description) "
                + "VALUES (?, ?, ?, ?)";

        String insertEventSQL =
                "INSERT INTO ThreatEvents "
                + "(threat_id, event_date, event_count) "
                + "VALUES (?, ?, ?)";

        int importedRecords = 0;
        int newThreats = 0;

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                throw new SQLException("Database connection failed.");
            }

            con.setAutoCommit(false);

            try (
                    PreparedStatement findThreat =
                            con.prepareStatement(findThreatSQL);

                    PreparedStatement insertThreat =
                            con.prepareStatement(
                                    insertThreatSQL,
                                    Statement.RETURN_GENERATED_KEYS
                            );

                    PreparedStatement insertEvent =
                            con.prepareStatement(insertEventSQL)
            ) {

                for (int i = 0; i < model.getRowCount(); i++) {

                    String name =
                            model.getValueAt(i, 0).toString().trim();

                    String category =
                            model.getValueAt(i, 1).toString().trim();

                    String severity =
                            model.getValueAt(i, 2).toString().trim();

                    String description =
                            model.getValueAt(i, 3).toString().trim();

                    String date =
                            model.getValueAt(i, 4).toString().trim();

                    int eventCount =
                            Integer.parseInt(
                                    model.getValueAt(i, 5)
                                            .toString().trim()
                            );

                    if (name.isEmpty()
                            || category.isEmpty()
                            || severity.isEmpty()
                            || date.isEmpty()
                            || eventCount < 0) {

                        throw new Exception(
                                "Invalid data in CSV row " + (i + 2)
                        );
                    }

                    if (!date.matches("\\d{4}-\\d{2}-\\d{2}")) {
                        throw new Exception(
                                "Invalid date in CSV row " + (i + 2)
                        );
                    }

                    findThreat.setString(1, name);

                    int threatId;

                    try (ResultSet rs = findThreat.executeQuery()) {

                        if (rs.next()) {

                            threatId = rs.getInt("threat_id");

                        } else {

                            insertThreat.setString(1, name);
                            insertThreat.setString(2, category);
                            insertThreat.setString(3, severity);
                            insertThreat.setString(4, description);

                            insertThreat.executeUpdate();

                            try (ResultSet keys =
                                    insertThreat.getGeneratedKeys()) {

                                if (!keys.next()) {
                                    throw new SQLException(
                                            "Could not retrieve Threat ID."
                                    );
                                }

                                threatId = keys.getInt(1);
                            }

                            newThreats++;
                        }
                    }

                    insertEvent.setInt(1, threatId);
                    insertEvent.setString(2, date);
                    insertEvent.setInt(3, eventCount);

                    insertEvent.executeUpdate();

                    importedRecords++;
                }

                con.commit();

                JOptionPane.showMessageDialog(
                        this,
                        "Dataset imported successfully!\n\n"
                        + "Observations added: " + importedRecords
                        + "\nNew threats created: " + newThreats
                );

            } catch (Exception e) {

                con.rollback();
                throw e;

            } finally {

                con.setAutoCommit(true);
            }

        } catch (Exception e) {

            JOptionPane.showMessageDialog(
                    this,
                    "Import failed: " + e.getMessage()
            );
        }
    }

    private void clearData() {

        model.setRowCount(0);
        selectedFile = null;

        JOptionPane.showMessageDialog(
                this,
                "Dataset preview cleared."
        );
    }

    // ==========================================
    // LIVE CISA DATASET
    // ==========================================

    private JPanel createCISAPanel() {

        JPanel panel = new JPanel(new BorderLayout());

        String[] columns = {
            "CVE ID",
            "Vendor",
            "Product",
            "Vulnerability Name",
            "Date Added",
            "Ransomware Use"
        };

        cisaModel = new DefaultTableModel(columns, 0) {

            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        cisaTable = new JTable(cisaModel);
        cisaTable.setRowHeight(25);

        JButton fetchButton =
                new JButton("Fetch Latest CISA Data");

        JButton refreshButton =
                new JButton("Refresh Database");

        JPanel topPanel = new JPanel();

        topPanel.add(fetchButton);
        topPanel.add(refreshButton);

        cisaStatusLabel = new JLabel(
                "CISA dataset ready.",
                SwingConstants.CENTER
        );

        JPanel bottomPanel = new JPanel(new BorderLayout());

        bottomPanel.add(cisaStatusLabel, BorderLayout.NORTH);

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(new JScrollPane(cisaTable), BorderLayout.CENTER);
        panel.add(bottomPanel, BorderLayout.SOUTH);

        fetchButton.addActionListener(e -> fetchCISAData());

        refreshButton.addActionListener(e -> loadCISAData());

        loadCISAData();

        return panel;
    }

    private void fetchCISAData() {

        cisaStatusLabel.setText("Fetching latest CISA vulnerabilities...");

        SwingWorker<Integer, Void> worker =
                new SwingWorker<>() {

            @Override
            protected Integer doInBackground() throws Exception {

                CISADataFetcher fetcher = new CISADataFetcher();

                return fetcher.fetchAndSaveData();
            }

            @Override
            protected void done() {

                try {

                    int count = get();

                    loadCISAData();

                    cisaStatusLabel.setText(
                            "CISA data processed successfully: "
                            + count + " records."
                    );

                    JOptionPane.showMessageDialog(
                            DatasetImportFrame.this,
                            "CISA data updated successfully!\n"
                            + "Records processed: " + count
                    );

                } catch (Exception e) {

                    cisaStatusLabel.setText("CISA fetch failed.");

                    JOptionPane.showMessageDialog(
                            DatasetImportFrame.this,
                            "Unable to fetch CISA data:\n"
                            + e.getMessage()
                    );
                }
            }
        };

        worker.execute();
    }

    private void loadCISAData() {

        cisaModel.setRowCount(0);

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

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                throw new SQLException("Database connection failed.");
            }

            try (PreparedStatement pst = con.prepareStatement(sql);
                 ResultSet rs = pst.executeQuery()) {

                while (rs.next()) {

                    cisaModel.addRow(new Object[]{
                        rs.getString("cve_id"),
                        rs.getString("vendor"),
                        rs.getString("product"),
                        rs.getString("vulnerability_name"),
                        rs.getString("date_added"),
                        rs.getString("ransomware_use")
                    });
                }
            }

            cisaStatusLabel.setText(
                    "CISA database records: "
                    + cisaModel.getRowCount()
            );

        } catch (SQLException e) {

            cisaStatusLabel.setText("Unable to load CISA dataset.");

            JOptionPane.showMessageDialog(
                    this,
                    "CISA database error:\n" + e.getMessage()
            );
        }
    }

    // ==========================================
    // CSV PARSER
    // ==========================================

    private String[] parseCSVLine(String line) {

        java.util.List<String> values =
                new java.util.ArrayList<>();

        StringBuilder value = new StringBuilder();

        boolean insideQuotes = false;

        for (int i = 0; i < line.length(); i++) {

            char current = line.charAt(i);

            if (current == '"') {

                if (insideQuotes
                        && i + 1 < line.length()
                        && line.charAt(i + 1) == '"') {

                    value.append('"');
                    i++;

                } else {

                    insideQuotes = !insideQuotes;
                }

            } else if (current == ',' && !insideQuotes) {

                values.add(value.toString());
                value.setLength(0);

            } else {

                value.append(current);
            }
        }

        values.add(value.toString());

        return values.toArray(String[]::new);
    }

    public static void main(String[] args) {

        SwingUtilities.invokeLater(() ->
                new DatasetImportFrame().setVisible(true)
        );
    }
}