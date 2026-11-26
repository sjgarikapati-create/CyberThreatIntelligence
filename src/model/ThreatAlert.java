package model;

public class ThreatAlert {

    private int alertId;
    private int threatId;
    private String alertDate;
    private String riskLevel;
    private String message;

    // Default Constructor
    public ThreatAlert() {
    }

    // Parameterized Constructor
    public ThreatAlert(int alertId, int threatId,
                       String alertDate, String riskLevel,
                       String message) {

        this.alertId = alertId;
        this.threatId = threatId;
        this.alertDate = alertDate;
        this.riskLevel = riskLevel;
        this.message = message;
    }

    // Getters and Setters

    public int getAlertId() {
        return alertId;
    }

    public void setAlertId(int alertId) {
        this.alertId = alertId;
    }

    public int getThreatId() {
        return threatId;
    }

    public void setThreatId(int threatId) {
        this.threatId = threatId;
    }

    public String getAlertDate() {
        return alertDate;
    }

    public void setAlertDate(String alertDate) {
        this.alertDate = alertDate;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

}