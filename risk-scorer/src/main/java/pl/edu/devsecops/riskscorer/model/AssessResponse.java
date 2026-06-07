package pl.edu.devsecops.riskscorer.model;

import java.util.Map;

/**
 * Odpowiedź Risk Scorera zawierająca wynik i decyzję dla pipeline.
 */
public class AssessResponse {

    private int score;
    private int threshold;
    private String decision;       // "PASS" lub "BLOCK"
    private Map<String, Integer> breakdown;  // ile znalezisk per severity
    private String summary;

    public AssessResponse(int score, int threshold, Map<String, Integer> breakdown) {
        this.score = score;
        this.threshold = threshold;
        this.breakdown = breakdown;
        this.decision = score >= threshold ? "BLOCK" : "PASS";
        this.summary = buildSummary();
    }

    private String buildSummary() {
        return String.format(
            "Risk score: %d/%d | Decision: %s | CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d",
            score, threshold, decision,
            breakdown.getOrDefault("CRITICAL", 0),
            breakdown.getOrDefault("HIGH", 0),
            breakdown.getOrDefault("MEDIUM", 0),
            breakdown.getOrDefault("LOW", 0)
        );
    }

    public int getScore() { return score; }
    public int getThreshold() { return threshold; }
    public String getDecision() { return decision; }
    public Map<String, Integer> getBreakdown() { return breakdown; }
    public String getSummary() { return summary; }
}
