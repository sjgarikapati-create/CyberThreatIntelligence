package model;

public class ThreatEvent {

    private int eventId;
    private int threatId;
    private String eventDate;
    private int eventCount;

    // Default Constructor
    public ThreatEvent() {
    }

    // Parameterized Constructor
    public ThreatEvent(int eventId, int threatId,
                       String eventDate, int eventCount) {

        this.eventId = eventId;
        this.threatId = threatId;
        this.eventDate = eventDate;
        this.eventCount = eventCount;
    }

    // Getters and Setters

    public int getEventId() {
        return eventId;
    }

    public void setEventId(int eventId) {
        this.eventId = eventId;
    }

    public int getThreatId() {
        return threatId;
    }

    public void setThreatId(int threatId) {
        this.threatId = threatId;
    }

    public String getEventDate() {
        return eventDate;
    }

    public void setEventDate(String eventDate) {
        this.eventDate = eventDate;
    }

    public int getEventCount() {
        return eventCount;
    }

    public void setEventCount(int eventCount) {
        this.eventCount = eventCount;
    }

}