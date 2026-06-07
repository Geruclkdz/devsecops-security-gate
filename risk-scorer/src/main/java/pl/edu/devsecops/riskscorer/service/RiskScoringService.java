package pl.edu.devsecops.riskscorer.service;

import org.springframework.stereotype.Service;
import pl.edu.devsecops.riskscorer.model.AssessRequest;
import pl.edu.devsecops.riskscorer.model.AssessResponse;
import pl.edu.devsecops.riskscorer.model.SemgrepFinding;

import java.util.HashMap;
import java.util.Map;

/**
 * Główna logika oceny ryzyka.
 *
 * Wagi oparte na CVSS v3 severity scale (NIST SP 800-218):
 *   CRITICAL = 40 pkt  (CVSS 9.0–10.0)
 *   HIGH     = 20 pkt  (CVSS 7.0–8.9)
 *   MEDIUM   =  5 pkt  (CVSS 4.0–6.9)
 *   LOW      =  1 pkt  (CVSS 0.1–3.9)
 *
 * Semgrep mapuje severity:
 *   ERROR   → HIGH
 *   WARNING → MEDIUM
 *   INFO    → LOW
 */
@Service
public class RiskScoringService {

    private static final Map<String, Integer> SEVERITY_WEIGHTS = Map.of(
        "CRITICAL", 40,
        "HIGH",     20,
        "MEDIUM",    5,
        "LOW",       1,
        // Mapowanie Semgrep → wagi
        "ERROR",    20,
        "WARNING",   5,
        "INFO",      1
    );

    public AssessResponse assess(AssessRequest request) {
        Map<String, Integer> breakdown = new HashMap<>();
        int totalScore = 0;

        for (SemgrepFinding finding : request.getFindings()) {
            String severity = finding.getSeverity() != null
                ? finding.getSeverity().toUpperCase()
                : "LOW";

            int weight = SEVERITY_WEIGHTS.getOrDefault(severity, 1);
            totalScore += weight;

            // Normalizuj nazwę do CRITICAL/HIGH/MEDIUM/LOW w breakdown
            String normalizedSeverity = normalizeSeverity(severity);
            breakdown.merge(normalizedSeverity, 1, Integer::sum);
        }

        return new AssessResponse(totalScore, request.getThreshold(), breakdown);
    }

    private String normalizeSeverity(String severity) {
        return switch (severity) {
            case "ERROR"   -> "HIGH";
            case "WARNING" -> "MEDIUM";
            case "INFO"    -> "LOW";
            default        -> severity;
        };
    }
}
