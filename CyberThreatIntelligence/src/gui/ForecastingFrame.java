package gui;

import processing.CISADataProcessor;
import processing.CISADataProcessor.WeeklyObservation;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.sql.SQLException;
import java.util.List;

public class ForecastingFrame extends JFrame {

    private final DefaultTableModel model;

    private final JLabel informationLabel;

    private final CISADataProcessor processor =
            new CISADataProcessor();

    private static final double ALPHA = 0.3;

    public ForecastingFrame() {

        setTitle("Live CISA Threat Forecasting");
        setSize(1100, 600);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(10, 10));

        JLabel heading = new JLabel(
                "CISA KEV Weekly Catalogue Additions Forecasting",
                SwingConstants.CENTER
        );

        heading.setFont(new Font("Arial", Font.BOLD, 23));

        heading.setBorder(
                BorderFactory.createEmptyBorder(20, 10, 15, 10)
        );

        add(heading, BorderLayout.NORTH);

        String[] columns = {
            "Forecast Method",
            "Observations",
            "Predicted Additions",
            "MAE",
            "RMSE"
        };

        model = new DefaultTableModel(columns, 0) {

            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        JTable table = new JTable(model);

        table.setRowHeight(35);

        add(new JScrollPane(table), BorderLayout.CENTER);

        informationLabel = new JLabel(
                "Loading live CISA data...",
                SwingConstants.CENTER
        );

        informationLabel.setFont(
                new Font("Arial", Font.PLAIN, 14)
        );

        JButton refreshButton =
                new JButton("Refresh Forecast");

        refreshButton.addActionListener(
                e -> loadForecasts()
        );

        JPanel bottomPanel = new JPanel(new BorderLayout());

        bottomPanel.add(
                informationLabel,
                BorderLayout.NORTH
        );

        bottomPanel.add(
                refreshButton,
                BorderLayout.SOUTH
        );

        bottomPanel.setBorder(
                BorderFactory.createEmptyBorder(10, 15, 15, 15)
        );

        add(bottomPanel, BorderLayout.SOUTH);

        loadForecasts();
    }

    private void loadForecasts() {

        model.setRowCount(0);

        try {

            List<WeeklyObservation> observations =
                    processor.getAllWeeklyObservations();

            if (observations.size() < 5) {

                informationLabel.setText(
                        "Insufficient weekly observations for forecasting."
                );

                return;
            }

            double naiveForecast =
                    calculateNaiveForecast(observations);

            double movingAverageForecast =
                    calculateMovingAverage(observations);

            double exponentialForecast =
                    calculateExponentialSmoothing(observations);

            double[] naiveErrors =
                    calculateErrors(observations, "NAIVE");

            double[] movingErrors =
                    calculateErrors(observations, "MOVING");

            double[] exponentialErrors =
                    calculateErrors(observations, "EXPONENTIAL");

            addForecastRow(
                    "Naive Forecast",
                    observations.size(),
                    naiveForecast,
                    naiveErrors
            );

            addForecastRow(
                    "Moving Average (4 Weeks)",
                    observations.size(),
                    movingAverageForecast,
                    movingErrors
            );

            addForecastRow(
                    "Exponential Smoothing",
                    observations.size(),
                    exponentialForecast,
                    exponentialErrors
            );

            informationLabel.setText(
                    "Live CISA observations: "
                    + observations.size()
                    + " | Exponential smoothing alpha: "
                    + ALPHA
            );

        } catch (SQLException e) {

            JOptionPane.showMessageDialog(
                    this,
                    "Unable to load CISA forecasting data:\n"
                    + e.getMessage(),
                    "Forecasting Error",
                    JOptionPane.ERROR_MESSAGE
            );
        }
    }

    // Naive forecasting:
    // The next prediction equals the latest observation.

    private double calculateNaiveForecast(
            List<WeeklyObservation> observations) {

        return observations.get(
                observations.size() - 1
        ).getCount();
    }

    // Moving average:
    // Uses the latest four weekly observations.

    private double calculateMovingAverage(
            List<WeeklyObservation> observations) {

        int size = observations.size();

        int start = Math.max(0, size - 4);

        double total = 0;

        for (int i = start; i < size; i++) {

            total += observations.get(i).getCount();
        }

        return total / (size - start);
    }

    // Simple exponential smoothing.

    private double calculateExponentialSmoothing(
            List<WeeklyObservation> observations) {

        double smoothedValue =
                observations.get(0).getCount();

        for (int i = 1; i < observations.size(); i++) {

            double actual =
                    observations.get(i).getCount();

            smoothedValue =
                    ALPHA * actual
                    + (1 - ALPHA) * smoothedValue;
        }

        return smoothedValue;
    }

    // Walk-forward validation.
    // Each prediction uses only observations before the target week.

    private double[] calculateErrors(
            List<WeeklyObservation> observations,
            String method) {

        double absoluteErrorTotal = 0;
        double squaredErrorTotal = 0;

        int predictionCount = 0;

        for (int i = 4; i < observations.size(); i++) {

            double prediction = 0;

            if (method.equals("NAIVE")) {

                prediction =
                        observations.get(i - 1).getCount();
            }

            else if (method.equals("MOVING")) {

                double total = 0;

                for (int j = i - 4; j < i; j++) {

                    total += observations.get(j).getCount();
                }

                prediction = total / 4;
            }

            else if (method.equals("EXPONENTIAL")) {

                double smoothed =
                        observations.get(0).getCount();

                for (int j = 1; j < i; j++) {

                    double actual =
                            observations.get(j).getCount();

                    smoothed =
                            ALPHA * actual
                            + (1 - ALPHA) * smoothed;
                }

                prediction = smoothed;
            }

            double actual =
                    observations.get(i).getCount();

            double error = actual - prediction;

            absoluteErrorTotal += Math.abs(error);

            squaredErrorTotal += error * error;

            predictionCount++;
        }

        if (predictionCount == 0) {
            return new double[]{0, 0};
        }

        double mae =
                absoluteErrorTotal / predictionCount;

        double rmse =
                Math.sqrt(
                        squaredErrorTotal / predictionCount
                );

        return new double[]{mae, rmse};
    }

    private void addForecastRow(
            String method,
            int observations,
            double forecast,
            double[] errors) {

        model.addRow(new Object[]{

            method,

            observations,

            String.format("%.2f", forecast),

            String.format("%.2f", errors[0]),

            String.format("%.2f", errors[1])
        });
    }

    public static void main(String[] args) {

        SwingUtilities.invokeLater(() -> {

            new ForecastingFrame().setVisible(true);

        });
    }
}