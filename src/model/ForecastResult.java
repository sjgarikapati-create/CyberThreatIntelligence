package model;

public class ForecastResult {

    private int threatId;
    private String threatName;
    private double predictedActivity;
    private String riskLevel;

    public ForecastResult() {
    }

    public ForecastResult(int threatId, String threatName,
                          double predictedActivity,
                          String riskLevel) {

        this.threatId = threatId;
        this.threatName = threatName;
        this.predictedActivity = predictedActivity;
        this.riskLevel = riskLevel;
    }

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

    public double getPredictedActivity() {
        return predictedActivity;
    }

    public void setPredictedActivity(double predictedActivity) {
        this.predictedActivity = predictedActivity;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }
}