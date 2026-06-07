package pl.edu.devsecops.riskscorer.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Reprezentuje pojedyncze znalezisko z raportu Semgrep.
 * Semgrep zwraca severity jako: ERROR (=HIGH), WARNING (=MEDIUM), INFO (=LOW)
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SemgrepFinding {

    @JsonProperty("check_id")
    private String checkId;

    private String severity;
    private String message;
    private String path;

    public String getCheckId() { return checkId; }
    public void setCheckId(String checkId) { this.checkId = checkId; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }

    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }
}
