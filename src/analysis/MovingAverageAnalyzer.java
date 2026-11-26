package analysis;

import java.util.List;
import model.ThreatEvent;

public class MovingAverageAnalyzer {

    public double calculateMovingAverage(
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

}