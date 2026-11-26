package analysis;

import java.util.List;
import java.util.ArrayList;
import model.ThreatEvent;
import processing.CISADataProcessor;
import processing.CISADataProcessor.WeeklyObservation;
import java.sql.SQLException;

public class EmergingThreatDetector {

    private static final double INCREASE_THRESHOLD = 50.0;

    private static final int RECENT_WINDOW = 2;

    private static final int CISA_WINDOW = 4;

    private static final int MINIMUM_RECENT_ADDITIONS = 8;

    private static final int MINIMUM_ACTIVE_WEEKS = 2;

    private static final double MINIMUM_BASELINE = 1.0;

    private final CISADataProcessor processor =
            new CISADataProcessor();

    // =========================================
    // EMERGING SIGNAL MODEL
    // =========================================

    public static class EmergingSignal {

        private final String week;
        private final double historicalAverage;
        private final double recentAverage;
        private final double growthRate;
        private final String status;

        public EmergingSignal(
                String week,
                double historicalAverage,
                double recentAverage,
                double growthRate,
                String status) {

            this.week = week;
            this.historicalAverage = historicalAverage;
            this.recentAverage = recentAverage;
            this.growthRate = growthRate;
            this.status = status;
        }

        public String getWeek() {
            return week;
        }

        public double getHistoricalAverage() {
            return historicalAverage;
        }

        public double getRecentAverage() {
            return recentAverage;
        }

        public double getGrowthRate() {
            return growthRate;
        }

        public String getStatus() {
            return status;
        }
    }

    // =========================================
    // EXISTING SYNTHETIC DETECTION METHODS
    // =========================================

    public double calculateHistoricalAverage(
            List<ThreatEvent> events) {

        if (events == null || events.size() <= RECENT_WINDOW) {
            return 0;
        }

        double total = 0;

        int historicalCount = events.size() - RECENT_WINDOW;

        for (int i = 0; i < historicalCount; i++) {
            total += events.get(i).getEventCount();
        }

        return total / historicalCount;
    }

    public double calculateRecentAverage(
            List<ThreatEvent> events) {

        if (events == null || events.size() < RECENT_WINDOW) {
            return 0;
        }

        double total = 0;

        for (int i = events.size() - RECENT_WINDOW;
             i < events.size(); i++) {

            total += events.get(i).getEventCount();
        }

        return total / RECENT_WINDOW;
    }

    public double calculatePercentageIncrease(
            List<ThreatEvent> events) {

        double historicalAverage =
                calculateHistoricalAverage(events);

        double recentAverage =
                calculateRecentAverage(events);

        if (historicalAverage == 0) {
            return recentAverage > 0
                    ? Double.POSITIVE_INFINITY : 0;
        }

        return ((recentAverage - historicalAverage)
                / historicalAverage) * 100;
    }

    public String detectEmergingThreat(
            List<ThreatEvent> events) {

        if (events == null || events.size() < 4) {
            return "INSUFFICIENT DATA";
        }

        double historicalAverage =
                calculateHistoricalAverage(events);

        double increase =
                calculatePercentageIncrease(events);

        boolean persistentIncrease = true;

        for (int i = events.size() - RECENT_WINDOW;
             i < events.size(); i++) {

            if (events.get(i).getEventCount()
                    <= historicalAverage) {

                persistentIncrease = false;
                break;
            }
        }

        if (increase >= INCREASE_THRESHOLD
                && persistentIncrease) {

            return "EMERGING THREAT";
        }

        return "NOT EMERGING";
    }

    // =========================================
    // IMPROVED LIVE CISA DETECTION
    // =========================================

    public List<EmergingSignal> detectCISAEmergingSignals()
            throws SQLException {

        List<WeeklyObservation> data =
                processor.getAllWeeklyObservations();

        List<EmergingSignal> signals =
                new ArrayList<>();

        int requiredWeeks = CISA_WINDOW * 2;

        if (data.size() < requiredWeeks) {
            return signals;
        }

        for (int i = requiredWeeks; i < data.size(); i++) {

            double historicalTotal = 0;
            double recentTotal = 0;

            int activeRecentWeeks = 0;
            int weeksAboveBaseline = 0;

            // Previous four weeks
            for (int j = i - 8; j < i - 4; j++) {

                historicalTotal +=
                        data.get(j).getCount();
            }

            double historicalAverage =
                    historicalTotal / CISA_WINDOW;

            // Latest four weeks
            for (int j = i - 4; j < i; j++) {

                int count = data.get(j).getCount();

                recentTotal += count;

                if (count > 0) {
                    activeRecentWeeks++;
                }

                if (count > historicalAverage) {
                    weeksAboveBaseline++;
                }
            }

            double recentAverage =
                    recentTotal / CISA_WINDOW;

            // Prevent extremely large percentages
            // when the historical average is close to zero.
            double safeBaseline = Math.max(
                    historicalAverage,
                    MINIMUM_BASELINE
            );

            double growthRate =
                    ((recentAverage - historicalAverage)
                    / safeBaseline) * 100;

            // Apply all detection conditions
            boolean sufficientActivity =
                    recentTotal >= MINIMUM_RECENT_ADDITIONS;

            boolean repeatedActivity =
                    activeRecentWeeks >= MINIMUM_ACTIVE_WEEKS;

            boolean persistentIncrease =
                    weeksAboveBaseline >= MINIMUM_ACTIVE_WEEKS;

            boolean significantGrowth =
                    growthRate >= INCREASE_THRESHOLD;

            String status = "NORMAL";

            if (sufficientActivity
                    && repeatedActivity
                    && persistentIncrease
                    && significantGrowth) {

                status = "EMERGING";
            }

            signals.add(
                    new EmergingSignal(
                            data.get(i).getWeek(),
                            historicalAverage,
                            recentAverage,
                            growthRate,
                            status
                    )
            );
        }

        return signals;
    }
}