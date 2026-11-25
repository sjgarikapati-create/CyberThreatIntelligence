package charts;

import processing.CISADataProcessor;
import processing.CISADataProcessor.WeeklyObservation;
import processing.CISADataProcessor.VendorSummary;
import dao.DashboardDAO;

import javax.swing.*;
import java.awt.*;
import java.sql.SQLException;
import java.util.List;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;

public class ThreatActivityChart extends JFrame {

    private final DefaultCategoryDataset barDataset;
    private final DefaultPieDataset<String> pieDataset;
    private final DefaultCategoryDataset lineDataset;

    private final CISADataProcessor processor =
            new CISADataProcessor();

    private final DashboardDAO dashboardDAO =
            new DashboardDAO();

    public ThreatActivityChart() {

        setTitle("Live CISA Intelligence Charts");
        setSize(1100, 700);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        barDataset = new DefaultCategoryDataset();
        pieDataset = new DefaultPieDataset<>();
        lineDataset = new DefaultCategoryDataset();

        loadDataFromDatabase();

        JTabbedPane tabs = new JTabbedPane();

        tabs.addTab("Top Vendors", createBarChart());
        tabs.addTab("Ransomware Distribution", createPieChart());
        tabs.addTab("Weekly CISA Trend", createLineChart());

        add(tabs, BorderLayout.CENTER);

        JButton refreshButton = new JButton("Refresh Charts");

        refreshButton.addActionListener(e -> refreshCharts());

        JPanel bottomPanel = new JPanel();
        bottomPanel.add(refreshButton);

        add(bottomPanel, BorderLayout.SOUTH);
    }

    private void loadDataFromDatabase() {

        try {

            // Load top 10 vendors
            List<VendorSummary> vendors =
                    processor.getTopVendors();

            for (VendorSummary vendor : vendors) {

                barDataset.addValue(
                        vendor.getCount(),
                        "Vulnerabilities",
                        vendor.getVendor()
                );
            }

            // Load ransomware distribution
            int total =
                    dashboardDAO.getTotalCISAVulnerabilities();

            int ransomware =
                    dashboardDAO.getRansomwareVulnerabilities();

            int other = total - ransomware;

            pieDataset.setValue(
                    "Ransomware Associated",
                    ransomware
            );

            pieDataset.setValue(
                    "Other / Unknown",
                    other
            );

            // Load weekly CISA catalogue additions
            List<WeeklyObservation> observations =
                    processor.getAllWeeklyObservations();

            int start = Math.max(
                    0,
                    observations.size() - 26
            );

            for (int i = start; i < observations.size(); i++) {

                WeeklyObservation observation =
                        observations.get(i);

                lineDataset.addValue(
                        observation.getCount(),
                        "Catalogue Additions",
                        observation.getWeek()
                );
            }

        } catch (SQLException e) {

            JOptionPane.showMessageDialog(
                    this,
                    "Unable to load CISA chart data:\n"
                    + e.getMessage(),
                    "Database Error",
                    JOptionPane.ERROR_MESSAGE
            );
        }
    }

    private JPanel createBarChart() {

        JFreeChart chart = ChartFactory.createBarChart(
                "Top 10 Vendors by Vulnerability Count",
                "Vendor",
                "Number of Vulnerabilities",
                barDataset
        );

        return new ChartPanel(chart);
    }

    private JPanel createPieChart() {

        JFreeChart chart = ChartFactory.createPieChart(
                "CISA Ransomware Association Distribution",
                pieDataset,
                true,
                true,
                false
        );

        return new ChartPanel(chart);
    }

    private JPanel createLineChart() {

        JFreeChart chart = ChartFactory.createLineChart(
                "Weekly CISA Catalogue Additions - Last 26 Weeks",
                "Week Starting",
                "Number of Additions",
                lineDataset
        );

        return new ChartPanel(chart);
    }

    private void refreshCharts() {

        barDataset.clear();
        pieDataset.clear();
        lineDataset.clear();

        loadDataFromDatabase();

    }
}