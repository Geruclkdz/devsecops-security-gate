package pl.edu.devsecops.riskscorer.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pl.edu.devsecops.riskscorer.model.AssessRequest;
import pl.edu.devsecops.riskscorer.model.AssessResponse;
import pl.edu.devsecops.riskscorer.service.RiskScoringService;

@RestController
@RequestMapping("/api")
public class RiskScorerController {

    private final RiskScoringService scoringService;

    public RiskScorerController(RiskScoringService scoringService) {
        this.scoringService = scoringService;
    }

    /**
     * POST /api/assess
     * Przyjmuje znaleziska z Semgrep, zwraca risk score i decyzję PASS/BLOCK.
     */
    @PostMapping("/assess")
    public ResponseEntity<AssessResponse> assess(@RequestBody AssessRequest request) {
        AssessResponse response = scoringService.assess(request);
        // HTTP 200 dla PASS, HTTP 422 dla BLOCK — pipeline odczyta kod HTTP
        int httpStatus = "BLOCK".equals(response.getDecision()) ? 422 : 200;
        return ResponseEntity.status(httpStatus).body(response);
    }

    /**
     * GET /api/health
     * Endpoint do sprawdzenia czy serwis działa.
     */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("Risk Scorer is running");
    }
}
