package gui;

import dao.GroundTruthDAO;
import database.DatabaseConnection;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.sql.*;

public class GroundTruthFrame extends JFrame {

    private final GroundTruthDAO dao;

    private JTable threatTable;
    private DefaultTableModel threatModel;
    private JComboBox<String> threatStatusBox;
    private int selectedThreatId = -1;

    private JTable cisaTable;
    private DefaultTableModel cisaModel;
    private JComboBox<String> cisaStatusBox;
    private String selectedCVE = null;

    public GroundTruthFrame() {

        dao = new GroundTruthDAO();

        dao.createTable();
        dao.createCISAGroundTruthTable();

        setTitle("Ground Truth Management");
        setSize(1150, 700);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout());

        JLabel heading = new JLabel(
                "GROUND TRUTH MANAGEMENT",
                SwingConstants.CENTER
        );

        heading.setFont(new Font("Arial", Font.BOLD, 24));
        heading.setBorder(
                BorderFactory.createEmptyBorder(15, 10, 15, 10)
        );

        add(heading, BorderLayout.NORTH);

        JTabbedPane tabs = new JTabbedPane();

        tabs.addTab("Synthetic Ground Truth", createSyntheticPanel());
        tabs.addTab("CISA Ground Truth", createCISAPanel());

        add(tabs, BorderLayout.CENTER);
    }

    // =====================================
    // SYNTHETIC GROUND TRUTH
    // =====================================

    private JPanel createSyntheticPanel() {

        JPanel panel = new JPanel(new BorderLayout(10, 10));

        String[] columns = {
            "Threat ID",
            "Threat Name",
            "Category",
            "Severity",
            "Actual Status"
        };

        threatModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        threatTable = new JTable(threatModel);
        threatTable.setRowHeight(28);

        panel.add(new JScrollPane(threatTable), BorderLayout.CENTER);

        JPanel bottom = new JPanel();

        threatStatusBox = new JComboBox<>(
                new String[]{"EMERGING", "NORMAL"}
        );

        JButton saveButton = new JButton("Save Actual Status");
        JButton refreshButton = new JButton("Refresh");

        bottom.add(new JLabel("Actual Status:"));
        bottom.add(threatStatusBox);
        bottom.add(saveButton);
        bottom.add(refreshButton);

        panel.add(bottom, BorderLayout.SOUTH);

        threatTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                loadSelectedThreat();
            }
        });

        saveButton.addActionListener(e -> saveSyntheticGroundTruth());
        refreshButton.addActionListener(e -> loadThreats());

        loadThreats();

        return panel;
    }

    private void loadThreats() {

        threatModel.setRowCount(0);

        String sql = """
            SELECT t.threat_id,
                   t.threat_name,
                   t.category,
                   t.severity,
                   g.actual_status
            FROM Threats t
            LEFT JOIN GroundTruth g
            ON t.threat_id = g.threat_id
            ORDER BY t.threat_id
            """;

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                throw new SQLException("Database connection failed.");
            }

            try (PreparedStatement pst = con.prepareStatement(sql);
                 ResultSet rs = pst.executeQuery()) {

                while (rs.next()) {

                    String status = rs.getString("actual_status");

                    threatModel.addRow(new Object[]{
                        rs.getInt("threat_id"),
                        rs.getString("threat_name"),
                        rs.getString("category"),
                        rs.getString("severity"),
                        status == null ? "NOT LABELLED" : status
                    });
                }
            }

        } catch (SQLException e) {
            showError("Unable to load synthetic threats", e);
        }
    }

    private void loadSelectedThreat() {

        int row = threatTable.getSelectedRow();

        if (row == -1) {
            selectedThreatId = -1;
            return;
        }

        selectedThreatId = Integer.parseInt(
                threatModel.getValueAt(row, 0).toString()
        );

        String status = threatModel.getValueAt(row, 4).toString();

        if (status.equals("EMERGING") || status.equals("NORMAL")) {
            threatStatusBox.setSelectedItem(status);
        } else {
            threatStatusBox.setSelectedItem("NORMAL");
        }
    }

    private void saveSyntheticGroundTruth() {

        if (selectedThreatId == -1) {
            JOptionPane.showMessageDialog(
                    this,
                    "Please select a threat first."
            );
            return;
        }

        String status = threatStatusBox.getSelectedItem().toString();

        if (dao.addGroundTruth(selectedThreatId, status)) {

            JOptionPane.showMessageDialog(
                    this,
                    "Synthetic ground truth saved successfully!"
            );

            selectedThreatId = -1;
            loadThreats();

        } else {
            JOptionPane.showMessageDialog(
                    this,
                    "Unable to save synthetic ground truth."
            );
        }
    }

    // =====================================
    // CISA GROUND TRUTH
    // =====================================

    private JPanel createCISAPanel() {

        JPanel panel = new JPanel(new BorderLayout(10, 10));

        String[] columns = {
            "CVE ID",
            "Vendor",
            "Product",
            "Date Added",
            "Ransomware Use",
            "Actual Status"
        };

        cisaModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        cisaTable = new JTable(cisaModel);
        cisaTable.setRowHeight(28);
        cisaTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        cisaTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        cisaTable.getColumnModel().getColumn(1).setPreferredWidth(130);
        cisaTable.getColumnModel().getColumn(2).setPreferredWidth(150);
        cisaTable.getColumnModel().getColumn(3).setPreferredWidth(110);
        cisaTable.getColumnModel().getColumn(4).setPreferredWidth(120);
        cisaTable.getColumnModel().getColumn(5).setPreferredWidth(120);

        panel.add(new JScrollPane(cisaTable), BorderLayout.CENTER);

        JPanel bottom = new JPanel();

        cisaStatusBox = new JComboBox<>(
                new String[]{"EMERGING", "NORMAL"}
        );

        JButton saveButton = new JButton("Save CISA Actual Status");
        JButton refreshButton = new JButton("Refresh CISA Records");

        bottom.add(new JLabel("Actual Status:"));
        bottom.add(cisaStatusBox);
        bottom.add(saveButton);
        bottom.add(refreshButton);

        panel.add(bottom, BorderLayout.SOUTH);

        cisaTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                loadSelectedCVE();
            }
        });

        saveButton.addActionListener(e -> saveCISAGroundTruth());
        refreshButton.addActionListener(e -> loadCISARecords());

        loadCISARecords();

        return panel;
    }

    private void loadCISARecords() {

        cisaModel.setRowCount(0);
        selectedCVE = null;

        String sql = """
            SELECT c.cve_id,
                   c.vendor,
                   c.product,
                   c.date_added,
                   c.ransomware_use,
                   g.actual_status
            FROM CISAVulnerabilities c
            LEFT JOIN CISAGroundTruth g
            ON c.cve_id = g.cve_id
            ORDER BY c.date_added DESC
            """;

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                throw new SQLException("Database connection failed.");
            }

            try (PreparedStatement pst = con.prepareStatement(sql);
                 ResultSet rs = pst.executeQuery()) {

                while (rs.next()) {

                    String status = rs.getString("actual_status");

                    cisaModel.addRow(new Object[]{
                        rs.getString("cve_id"),
                        rs.getString("vendor"),
                        rs.getString("product"),
                        rs.getString("date_added"),
                        rs.getString("ransomware_use"),
                        status == null ? "NOT LABELLED" : status
                    });
                }
            }

        } catch (SQLException e) {
            showError("Unable to load CISA records", e);
        }
    }

    private void loadSelectedCVE() {

        int row = cisaTable.getSelectedRow();

        if (row == -1) {
            selectedCVE = null;
            return;
        }

        selectedCVE = cisaModel.getValueAt(row, 0).toString();

        String status = cisaModel.getValueAt(row, 5).toString();

        if (status.equals("EMERGING") || status.equals("NORMAL")) {
            cisaStatusBox.setSelectedItem(status);
        } else {
            cisaStatusBox.setSelectedItem("NORMAL");
        }
    }

    private void saveCISAGroundTruth() {

        if (selectedCVE == null) {
            JOptionPane.showMessageDialog(
                    this,
                    "Please select a CISA vulnerability first."
            );
            return;
        }

        String status = cisaStatusBox.getSelectedItem().toString();

        int confirmation = JOptionPane.showConfirmDialog(
                this,
                "Save " + status + " as the actual status for "
                + selectedCVE + "?",
                "Confirm Ground Truth",
                JOptionPane.YES_NO_OPTION
        );

        if (confirmation != JOptionPane.YES_OPTION) {
            return;
        }

        boolean saved = dao.addCISAGroundTruth(selectedCVE, status);

        if (saved) {

            JOptionPane.showMessageDialog(
                    this,
                    "CISA ground truth saved successfully!"
            );

            loadCISARecords();

        } else {

            JOptionPane.showMessageDialog(
                    this,
                    "Unable to save CISA ground truth."
            );
        }
    }

    // =====================================
    // ERROR HANDLING
    // =====================================

    private void showError(String message, SQLException e) {

        JOptionPane.showMessageDialog(
                this,
                message + ":\n" + e.getMessage(),
                "Database Error",
                JOptionPane.ERROR_MESSAGE
        );
    }

    public static void main(String[] args) {

        SwingUtilities.invokeLater(() ->
                new GroundTruthFrame().setVisible(true)
        );
    }
}