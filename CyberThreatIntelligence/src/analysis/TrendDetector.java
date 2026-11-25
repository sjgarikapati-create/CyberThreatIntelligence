package analysis;

import java.util.List;
import model.ThreatEvent;

public class TrendDetector {

    public String detectTrend(List<ThreatEvent> events) {

        if (events == null || events.size() < 2) {
            return "INSUFFICIENT DATA";
        }

        int first = events.get(0).getEventCount();

        int last = events.get(events.size() - 1).getEventCount();

        if (last > first) {

            return "INCREASING";

        } else if (last < first) {

            return "DECREASING";

        } else {

            return "STABLE";
        }
    }
}