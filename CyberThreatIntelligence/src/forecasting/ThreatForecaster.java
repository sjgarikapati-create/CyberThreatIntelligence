package forecasting;

import java.util.List;
import model.ThreatEvent;

public class ThreatForecaster {

    // Forecast future threat activity using Moving Average
    public double forecastNextPeriod(
            List<ThreatEvent> events, int period) {

        if (events == null || period <= 0
                || events.size() < period) {

            return 0;
        }

        double total = 0;

        int start = events.size() - period;

        for (int i = start; i < events.size(); i++) {

            total += events.get(i).getEventCount();
        }

        return total / period;
    }

    // Calculate historical average
    public double calculateHistoricalAverage(
            List<ThreatEvent> events) {

        if (events == null || events.isEmpty()) {
            return 0;
        }

        double total = 0;

        for (ThreatEvent event : events) {
            total += event.getEventCount();
        }

        return total / events.size();
    }

    // Calculate percentage increase
    public double calculateGrowthRate(
            List<ThreatEvent> events) {

        if (events == null || events.size() < 2) {
            return 0;
        }

        int previous =
            events.get(events.size() - 2).getEventCount();

        int latest =
            events.get(events.size() - 1).getEventCount();

        if (previous == 0) {
            return latest > 0 ? 100 : 0;
        }

        return ((double)(latest - previous) / previous) * 100;
    }

    // Classify predicted threat risk
    public String classifyForecast(
            double forecast, double growthRate) {

        if (forecast >= 100 || growthRate >= 100) {
            return "HIGH";

        } else if (forecast >= 50 || growthRate >= 50) {
            return "MEDIUM";

        } else {
            return "LOW";
        }
    }

    // Maintain compatibility with existing code
    public String classifyForecast(double forecast) {

        return classifyForecast(forecast, 0);
    }
}