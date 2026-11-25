package gui;

import database.DatabaseConnection;
import processing.CISADataProcessor;
import processing.CISADataProcessor.WeeklyObservation;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.sql.*;
import java.util.List;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.axis.CategoryAxis;
import org.jfree.chart.axis.CategoryLabelPositions;
import org.jfree.data.category.DefaultCategoryDataset;

public class EvaluationFrame extends JFrame {

    private final JLabel totalLabel = new JLabel("0");
    private final JLabel labelledLabel = new JLabel("0");
    private final JLabel unlabelledLabel = new JLabel("0");

    private final JLabel tpLabel = new JLabel("0");
    private final JLabel tnLabel = new JLabel("0");
    private final JLabel fpLabel = new JLabel("0");
    private final JLabel fnLabel = new JLabel("0");

    private final JLabel precisionLabel = new JLabel("N/A");
    private final JLabel recallLabel = new JLabel("N/A");
    private final JLabel f1Label = new JLabel("N/A");
    private final JLabel accuracyLabel = new JLabel("N/A");

    private final JLabel bestMethodLabel = new JLabel(
            "Best Method: Calculating..."
    );

    private final DefaultTableModel forecastModel;

    private final JPanel chartHolder = new JPanel(new BorderLayout());

    private final CISADataProcessor processor =
            new CISADataProcessor();

    private static final double ALPHA = 0.3;
    private static final int CHART_WEEKS = 26;

    public EvaluationFrame() {

        setTitle("Cyber Threat Intelligence Evaluation");
        setSize(1250, 850);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout());

        JLabel heading = new JLabel(
                "CYBER THREAT INTELLIGENCE EVALUATION",
                SwingConstants.CENTER
        );

        heading.setFont(new Font("Arial", Font.BOLD, 23));
        heading.setBorder(
                BorderFactory.createEmptyBorder(15, 10, 15, 10)
        );

        add(heading, BorderLayout.NORTH);

        JTabbedPane tabs = new JTabbedPane();

        tabs.addTab(
                "Classification Evaluation",
                createClassificationPanel()
        );

        forecastModel = new DefaultTableModel(
                new String[]{
                    "Forecast Method",
                    "Test Predictions",
                    "MAE",
                    "RMSE"
                }, 0
        ) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        JTable forecastTable = new JTable(forecastModel);
        forecastTable.setRowHeight(32);

        JPanel forecastPanel = new JPanel(new BorderLayout(10, 10));

        JPanel tablePanel = new JPanel(new BorderLayout());

        tablePanel.add(
                new JScrollPane(forecastTable),
                BorderLayout.CENTER
        );

        bestMethodLabel.setFont(
                new Font("Arial", Font.BOLD, 16)
        );

        bestMethodLabel.setBorder(
                BorderFactory.createEmptyBorder(10, 10, 10, 10)
        );

        tablePanel.add(bestMethodLabel, BorderLayout.SOUTH);

        chartHolder.setBorder(
                BorderFactory.createTitledBorder(
                        "Actual vs Predicted Weekly CISA Additions"
                )
        );

        JSplitPane splitPane = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                tablePanel,
                chartHolder
        );

        splitPane.setResizeWeight(0.35);
        splitPane.setDividerLocation(220);

        forecastPanel.add(splitPane, BorderLayout.CENTER);

        JLabel note = new JLabel(
                "Evaluation uses historical CISA weekly catalogue additions "
                + "with walk-forward validation. Chart shows the latest "
                + "26 evaluated weeks.",
                SwingConstants.CENTER
        );

        note.setBorder(
                BorderFactory.createEmptyBorder(10, 5, 10, 5)
        );

        forecastPanel.add(note, BorderLayout.SOUTH);

        tabs.addTab(
                "CISA Forecasting Evaluation",
                forecastPanel
        );

        add(tabs, BorderLayout.CENTER);

        JButton refreshButton = new JButton("Refresh Evaluation");

        refreshButton.addActionListener(e -> refreshEvaluation());

        JPanel bottom = new JPanel();
        bottom.add(refreshButton);

        add(bottom, BorderLayout.SOUTH);

        refreshEvaluation();
    }

    // =====================================
    // CLASSIFICATION EVALUATION
    // =====================================

    private JPanel createClassificationPanel() {

        JPanel panel = new JPanel(new GridLayout(4, 3, 15, 15));

        panel.setBackground(new Color(241, 245, 249));

        panel.setBorder(
                BorderFactory.createEmptyBorder(20, 25, 20, 25)
        );

        addCard(panel, "TOTAL THREATS", totalLabel);
        addCard(panel, "LABELLED THREATS", labelledLabel);
        addCard(panel, "UNLABELLED THREATS", unlabelledLabel);

        addCard(panel, "TRUE POSITIVES", tpLabel);
        addCard(panel, "TRUE NEGATIVES", tnLabel);
        addCard(panel, "FALSE POSITIVES", fpLabel);
        addCard(panel, "FALSE NEGATIVES", fnLabel);

        addCard(panel, "PRECISION", precisionLabel);
        addCard(panel, "RECALL", recallLabel);
        addCard(panel, "F1 SCORE", f1Label);
        addCard(panel, "ACCURACY", accuracyLabel);

        return panel;
    }

    private void addCard(
            JPanel panel,
            String title,
            JLabel valueLabel) {

        JPanel card = new JPanel(new GridLayout(2, 1));
        card.setBackground(Color.WHITE);

        JLabel titleLabel = new JLabel(
                title,
                SwingConstants.CENTER
        );

        titleLabel.setFont(
                new Font("Arial", Font.BOLD, 13)
        );

        valueLabel.setFont(
                new Font("Arial", Font.BOLD, 24)
        );

        valueLabel.setForeground(new Color(37, 99, 235));

        card.add(titleLabel);
        card.add(valueLabel);

        panel.add(card);
    }

    private void refreshEvaluation() {

        loadClassificationEvaluation();
        loadForecastEvaluation();
    }

    private void loadClassificationEvaluation() {

        String sql = """
            SELECT
                COUNT(*) AS total_threats,

                SUM(CASE
                    WHEN g.actual_status IS NOT NULL
                    THEN 1 ELSE 0
                END) AS labelled,

                SUM(CASE
                    WHEN g.actual_status IS NULL
                    THEN 1 ELSE 0
                END) AS unlabelled,

                SUM(CASE
                    WHEN g.actual_status = 'EMERGING'
                    AND a.threat_id IS NOT NULL
                    THEN 1 ELSE 0
                END) AS tp,

                SUM(CASE
                    WHEN g.actual_status = 'NORMAL'
                    AND a.threat_id IS NULL
                    THEN 1 ELSE 0
                END) AS tn,

                SUM(CASE
                    WHEN g.actual_status = 'NORMAL'
                    AND a.threat_id IS NOT NULL
                    THEN 1 ELSE 0
                END) AS fp,

                SUM(CASE
                    WHEN g.actual_status = 'EMERGING'
                    AND a.threat_id IS NULL
                    THEN 1 ELSE 0
                END) AS fn

            FROM Threats t

            LEFT JOIN GroundTruth g
            ON t.threat_id = g.threat_id

            LEFT JOIN (
                SELECT DISTINCT threat_id
                FROM Alerts
                WHERE risk_level = 'EMERGING'
            ) a

            ON t.threat_id = a.threat_id
            """;

        try (Connection con = DatabaseConnection.getConnection()) {

            if (con == null) {
                throw new SQLException("Database connection failed.");
            }

            try (PreparedStatement pst = con.prepareStatement(sql);
                 ResultSet rs = pst.executeQuery()) {

                if (rs.next()) {

                    int total = rs.getInt("total_threats");
                    int labelled = rs.getInt("labelled");
                    int unlabelled = rs.getInt("unlabelled");

                    int tp = rs.getInt("tp");
                    int tn = rs.getInt("tn");
                    int fp = rs.getInt("fp");
                    int fn = rs.getInt("fn");

                    totalLabel.setText(String.valueOf(total));
                    labelledLabel.setText(String.valueOf(labelled));
                    unlabelledLabel.setText(String.valueOf(unlabelled));

                    tpLabel.setText(String.valueOf(tp));
                    tnLabel.setText(String.valueOf(tn));
                    fpLabel.setText(String.valueOf(fp));
                    fnLabel.setText(String.valueOf(fn));

                    if (labelled == 0) {
                        precisionLabel.setText("N/A");
                        recallLabel.setText("N/A");
                        f1Label.setText("N/A");
                        accuracyLabel.setText("N/A");
                        return;
                    }

                    double precision =
                            (tp + fp) == 0 ? 0 :
                            (double) tp / (tp + fp);

                    double recall =
                            (tp + fn) == 0 ? 0 :
                            (double) tp / (tp + fn);

                    double f1 =
                            (precision + recall) == 0 ? 0 :
                            2 * precision * recall /
                            (precision + recall);

                    double accuracy =
                            (double) (tp + tn) / labelled;

                    precisionLabel.setText(
                            String.format("%.2f%%", precision * 100)
                    );

                    recallLabel.setText(
                            String.format("%.2f%%", recall * 100)
                    );

                    f1Label.setText(
                            String.format("%.2f%%", f1 * 100)
                    );

                    accuracyLabel.setText(
                            String.format("%.2f%%", accuracy * 100)
                    );
                }
            }

        } catch (SQLException e) {
            showError(e);
        }
    }

    // =====================================
    // CISA FORECASTING EVALUATION
    // =====================================

    private void loadForecastEvaluation() {

        forecastModel.setRowCount(0);
        chartHolder.removeAll();

        try {

            List<WeeklyObservation> data =
                    processor.getAllWeeklyObservations();

            if (data.size() <= 4) {

                bestMethodLabel.setText(
                        "Not enough weekly observations."
                );

                chartHolder.revalidate();
                chartHolder.repaint();
                return;
            }

            double[] naive = calculateErrors(data, 0);
            double[] moving = calculateErrors(data, 1);
            double[] exponential = calculateErrors(data, 2);

            int testCount = data.size() - 4;

            addForecastRow("Naive Forecast", testCount, naive);
            addForecastRow("Moving Average (4 Weeks)", testCount, moving);
            addForecastRow("Exponential Smoothing", testCount, exponential);

            updateBestMethod(naive, moving, exponential);

            createForecastChart(data);

        } catch (SQLException e) {
            showError(e);
        }
    }

    private double getPrediction(
            List<WeeklyObservation> data,
            int index,
            int method) {

        if (method == 0) {

            return data.get(index - 1).getCount();

        } else if (method == 1) {

            double total = 0;

            for (int j = index - 4; j < index; j++) {
                total += data.get(j).getCount();
            }

            return total / 4.0;

        } else {

            double smoothed = data.get(0).getCount();

            for (int j = 1; j < index; j++) {

                smoothed =
                        ALPHA * data.get(j).getCount()
                        + (1 - ALPHA) * smoothed;
            }

            return smoothed;
        }
    }

    private double[] calculateErrors(
            List<WeeklyObservation> data,
            int method) {

        double absoluteError = 0;
        double squaredError = 0;

        int predictions = 0;

        for (int i = 4; i < data.size(); i++) {

            double prediction = getPrediction(data, i, method);
            double actual = data.get(i).getCount();

            double error = actual - prediction;

            absoluteError += Math.abs(error);
            squaredError += error * error;

            predictions++;
        }

        if (predictions == 0) {
            return new double[]{0, 0};
        }

        double mae = absoluteError / predictions;

        double rmse = Math.sqrt(
                squaredError / predictions
        );

        return new double[]{mae, rmse};
    }

    // =====================================
    // BEST FORECAST METHOD
    // =====================================

    private void updateBestMethod(
            double[] naive,
            double[] moving,
            double[] exponential) {

        String bestMethod = "Naive Forecast";
        double bestMAE = naive[0];

        if (moving[0] < bestMAE) {
            bestMAE = moving[0];
            bestMethod = "Moving Average (4 Weeks)";
        }

        if (exponential[0] < bestMAE) {
            bestMAE = exponential[0];
            bestMethod = "Exponential Smoothing";
        }

        bestMethodLabel.setText(
                "Best Method (Lowest MAE): "
                + bestMethod
                + " | MAE: "
                + String.format("%.2f", bestMAE)
        );
    }

    // =====================================
    // ACTUAL VS PREDICTED CHART
    // =====================================

    private void createForecastChart(
            List<WeeklyObservation> data) {

        DefaultCategoryDataset dataset =
                new DefaultCategoryDataset();

        int start = Math.max(4, data.size() - CHART_WEEKS);

        for (int i = start; i < data.size(); i++) {

            String week = data.get(i).getWeek();

            double actual = data.get(i).getCount();

            double naive = getPrediction(data, i, 0);
            double moving = getPrediction(data, i, 1);
            double exponential = getPrediction(data, i, 2);

            dataset.addValue(actual, "Actual Additions", week);
            dataset.addValue(naive, "Naive Forecast", week);
            dataset.addValue(moving, "Moving Average", week);
            dataset.addValue(
                    exponential,
                    "Exponential Smoothing",
                    week
            );
        }

        JFreeChart chart = ChartFactory.createLineChart(
                "Actual vs Predicted CISA Weekly Additions",
                "Week Starting",
                "Number of CISA Additions",
                dataset,
                PlotOrientation.VERTICAL,
                true,
                true,
                false
        );

        CategoryPlot plot = chart.getCategoryPlot();

        CategoryAxis axis = plot.getDomainAxis();

        axis.setCategoryLabelPositions(
                CategoryLabelPositions.UP_45
        );

        ChartPanel chartPanel = new ChartPanel(chart);

        chartPanel.setMouseWheelEnabled(true);

        chartHolder.add(chartPanel, BorderLayout.CENTER);

        chartHolder.revalidate();
        chartHolder.repaint();
    }

    // =====================================
    // TABLE
    // =====================================

    private void addForecastRow(
            String method,
            int predictions,
            double[] errors) {

        forecastModel.addRow(new Object[]{
            method,
            predictions,
            String.format("%.2f", errors[0]),
            String.format("%.2f", errors[1])
        });
    }

    // =====================================
    // ERROR HANDLING
    // =====================================

    private void showError(SQLException e) {

        JOptionPane.showMessageDialog(
                this,
                "Evaluation error:\n" + e.getMessage(),
                "Database Error",
                JOptionPane.ERROR_MESSAGE
        );
    }

    public static void main(String[] args) {

        SwingUtilities.invokeLater(() ->
                new EvaluationFrame().setVisible(true)
        );
    }
}