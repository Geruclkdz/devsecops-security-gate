package pl.edu.devsecops.riskscorer;

import org.junit.jupiter.api.Test;
import pl.edu.devsecops.riskscorer.model.AssessRequest;
import pl.edu.devsecops.riskscorer.model.AssessResponse;
import pl.edu.devsecops.riskscorer.model.SemgrepFinding;
import pl.edu.devsecops.riskscorer.service.RiskScoringService;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RiskScoringServiceTest {

    private final RiskScoringService service = new RiskScoringService();

    private SemgrepFinding finding(String severity) {
        SemgrepFinding f = new SemgrepFinding();
        f.setSeverity(severity);
        f.setCheckId("test-rule");
        return f;
    }

    @Test
    void noFindings_shouldPass() {
        AssessRequest req = new AssessRequest();
        req.setFindings(List.of());
        req.setThreshold(70);
        AssessResponse res = service.assess(req);
        assertEquals(0, res.getScore());
        assertEquals("PASS", res.getDecision());
    }

    @Test
    void oneCritical_shouldBlock() {
        // 1 CRITICAL = 40 pkt > próg 70? Nie.
        // 2 CRITICAL = 80 pkt > 70 → BLOCK
        AssessRequest req = new AssessRequest();
        req.setFindings(List.of(finding("CRITICAL"), finding("CRITICAL")));
        req.setThreshold(70);
        AssessResponse res = service.assess(req);
        assertEquals(80, res.getScore());
        assertEquals("BLOCK", res.getDecision());
    }

    @Test
    void manyLow_shouldPass() {
        // 10 × LOW = 10 pkt < 70 → PASS
        AssessRequest req = new AssessRequest();
        req.setFindings(List.of(
            finding("LOW"), finding("LOW"), finding("LOW"),
            finding("LOW"), finding("LOW"), finding("LOW"),
            finding("LOW"), finding("LOW"), finding("LOW"), finding("LOW")
        ));
        req.setThreshold(70);
        AssessResponse res = service.assess(req);
        assertEquals(10, res.getScore());
        assertEquals("PASS", res.getDecision());
    }

    @Test
    void semgrepSeverityMapping_errorIsHigh() {
        // Semgrep zwraca "ERROR" — powinno być traktowane jak HIGH (20 pkt)
        AssessRequest req = new AssessRequest();
        req.setFindings(List.of(finding("ERROR")));
        req.setThreshold(70);
        AssessResponse res = service.assess(req);
        assertEquals(20, res.getScore());
        assertEquals("HIGH", res.getBreakdown().keySet().iterator().next());
    }

    @Test
    void customThreshold_shouldRespectIt() {
        // score=20, threshold=10 → BLOCK
        AssessRequest req = new AssessRequest();
        req.setFindings(List.of(finding("HIGH")));
        req.setThreshold(10);
        AssessResponse res = service.assess(req);
        assertEquals("BLOCK", res.getDecision());
    }
}
