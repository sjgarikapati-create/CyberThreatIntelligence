package gui;

import processing.CISADataProcessor;
import processing.CISADataProcessor.WeeklyObservation;
import processing.CISADataProcessor.VendorSummary;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.sql.SQLException;
import java.util.List;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.axis.CategoryAxis;
import org.jfree.chart.axis.CategoryLabelPositions;
import org.jfree.data.category.DefaultCategoryDataset;

public class CISAAnalysisFrame extends JFrame {

    private final JLabel totalLabel;
    private final JLabel ransomwareLabel;

    private final DefaultTableModel vendorModel;
    private final DefaultTableModel weeklyModel;

    private final DefaultCategoryDataset weeklyDataset;

    private final CISADataProcessor processor =
            new CISADataProcessor();

    public CISAAnalysisFrame() {

        setTitle("Live CISA Threat Analysis");
        setSize(1000, 650);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(10, 10));

        JLabel heading = new JLabel(
                "LIVE CISA THREAT ANALYSIS",
                SwingConstants.CENTER
        );

        heading.setFont(new Font("Arial", Font.BOLD, 24));
        heading.setBorder(
                BorderFactory.createEmptyBorder(15, 10, 10, 10)
        );

        add(heading, BorderLayout.NORTH);

        JPanel summaryPanel = new JPanel(
                new GridLayout(1, 2, 15, 10)
        );

        totalLabel = new JLabel(
                "Total Vulnerabilities: 0",
                SwingConstants.CENTER
        );

        ransomwareLabel = new JLabel(
                "Ransomware-Associated: 0",
                SwingConstants.CENTER
        );

        totalLabel.setFont(new Font("Arial", Font.BOLD, 18));
        ransomwareLabel.setFont(new Font("Arial", Font.BOLD, 18));

        summaryPanel.add(totalLabel);
        summaryPanel.add(ransomwareLabel);

        vendorModel = new DefaultTableModel(
                new String[]{"Vendor", "Number of Vulnerabilities"}, 0
        );

        weeklyModel = new DefaultTableModel(
                new String[]{"Week", "Catalogue Additions"}, 0
        );

        JTable vendorTable = new JTable(vendorModel);
        JTable weeklyTable = new JTable(weeklyModel);

        weeklyDataset = new DefaultCategoryDataset();

        JFreeChart weeklyChart = ChartFactory.createLineChart(
                "Weekly CISA Catalogue Additions - Last 26 Weeks",
                "Week",
                "Number of Vulnerabilities",
                weeklyDataset,
                PlotOrientation.VERTICAL,
                false,
                true,
                false
        );

        CategoryAxis axis =
                weeklyChart.getCategoryPlot().getDomainAxis();

        axis.setCategoryLabelPositions(
                CategoryLabelPositions.UP_45
        );

        ChartPanel chartPanel = new ChartPanel(weeklyChart);

        JTabbedPane tabs = new JTabbedPane();

        tabs.addTab(
                "Top 10 Vendors",
                new JScrollPane(vendorTable)
        );

        tabs.addTab(
                "Weekly Catalogue Additions",
                new JScrollPane(weeklyTable)
        );

        tabs.addTab(
                "Weekly Trend Chart",
                chartPanel
        );

        JPanel centerPanel = new JPanel(new BorderLayout(10, 10));

        centerPanel.setBorder(
                BorderFactory.createEmptyBorder(10, 15, 10, 15)
        );

        centerPanel.add(summaryPanel, BorderLayout.NORTH);
        centerPanel.add(tabs, BorderLayout.CENTER);

        add(centerPanel, BorderLayout.CENTER);

        JButton refreshButton = new JButton("Refresh Analysis");

        refreshButton.addActionListener(e -> loadAnalysis());

        JPanel bottomPanel = new JPanel();
        bottomPanel.add(refreshButton);

        add(bottomPanel, BorderLayout.SOUTH);

        loadAnalysis();
    }

    private void loadAnalysis() {

        vendorModel.setRowCount(0);
        weeklyModel.setRowCount(0);
        weeklyDataset.clear();

        try {

            // Get summary information from the processor
            totalLabel.setText(
                    "Total Vulnerabilities: "
                    + processor.getTotalVulnerabilities()
            );

            ransomwareLabel.setText(
                    "Ransomware-Associated: "
                    + processor.getRansomwareVulnerabilities()
            );

            // Get top 10 vendors
            List<VendorSummary> vendors =
                    processor.getTopVendors();

            for (VendorSummary vendor : vendors) {

                vendorModel.addRow(new Object[]{
                    vendor.getVendor(),
                    vendor.getCount()
                });
            }

            // Get all weekly observations
            List<WeeklyObservation> weeklyData =
                    processor.getAllWeeklyObservations();

            for (WeeklyObservation observation : weeklyData) {

                weeklyModel.addRow(new Object[]{
                    observation.getWeek(),
                    observation.getCount()
                });
            }

            // Get latest 26 weeks for the chart
            List<WeeklyObservation> latestWeeks =
                    processor.getLatestWeeklyObservations(26);

            for (WeeklyObservation observation : latestWeeks) {

                weeklyDataset.addValue(
                        observation.getCount(),
                        "Catalogue Additions",
                        observation.getWeek()
                );
            }

        } catch (SQLException e) {

            JOptionPane.showMessageDialog(
                    this,
                    "Unable to load CISA analysis:\n" + e.getMessage(),
                    "Database Error",
                    JOptionPane.ERROR_MESSAGE
            );
        }
    }

    public static void main(String[] args) {

        SwingUtilities.invokeLater(() -> {
            new CISAAnalysisFrame().setVisible(true);
        });
    }
}