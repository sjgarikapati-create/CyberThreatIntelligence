package analysis;

import java.util.List;
import model.ThreatEvent;

public class ThreatAnalyzer {

    // Calculate average threat activity
    public double calculateAverage(List<ThreatEvent> events) {

        if (events == null || events.isEmpty()) {
            return 0;
        }

        int total = 0;

        for (ThreatEvent event : events) {

            total += event.getEventCount();

        }

        return (double) total / events.size();
    }

    // Calculate total threat activity
    public int calculateTotal(List<ThreatEvent> events) {

        int total = 0;

        for (ThreatEvent event : events) {

            total += event.getEventCount();

        }

        return total;
    }

}