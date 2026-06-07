package pl.edu.devsecops.riskscorer.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Żądanie oceny ryzyka — zawiera listę znalezisk z Semgrep
 * oraz opcjonalny próg ryzyka (domyślnie 70).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AssessRequest {

    @JsonProperty("findings")
    private List<SemgrepFinding> findings;

    @JsonProperty("threshold")
    private int threshold = 70;

    public List<SemgrepFinding> getFindings() { return findings; }
    public void setFindings(List<SemgrepFinding> findings) { this.findings = findings; }

    public int getThreshold() { return threshold; }
    public void setThreshold(int threshold) { this.threshold = threshold; }
}
