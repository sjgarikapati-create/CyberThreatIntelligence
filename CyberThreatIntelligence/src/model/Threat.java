package model;

public class Threat {

    private int threatId;
    private String threatName;
    private String category;
    private String severity;
    private String description;

    // Default Constructor
    public Threat() {
    }

    // Parameterized Constructor
    public Threat(int threatId, String threatName,
                  String category, String severity,
                  String description) {

        this.threatId = threatId;
        this.threatName = threatName;
        this.category = category;
        this.severity = severity;
        this.description = description;
    }

    // Getters and Setters

    public int getThreatId() {
        return threatId;
    }

    public void setThreatId(int threatId) {
        this.threatId = threatId;
    }

    public String getThreatName() {
        return threatName;
    }

    public void setThreatName(String threatName) {
        this.threatName = threatName;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

}