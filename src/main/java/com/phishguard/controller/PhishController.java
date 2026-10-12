package com.phishguard.controller;

import com.phishguard.model.ScanResult;
import com.phishguard.service.PhishService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class PhishController {

    private final PhishService phishService;

    public PhishController(PhishService phishService) {
        this.phishService = phishService;
    }

    // POST /api/scan   body: {"url": "http://example.com"}
    @PostMapping("/scan")
    public ResponseEntity<ScanResult> scan(@RequestBody Map<String, String> body) {
        ScanResult result = phishService.scan(body.get("url"));
        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    // GET /api/scan/history?q=login&level=HIGH&sort=desc
    @GetMapping("/scan/history")
    public List<ScanResult> history(@RequestParam(defaultValue = "") String q,
                                    @RequestParam(defaultValue = "") String level,
                                    @RequestParam(defaultValue = "desc") String sort) {
        return phishService.getHistory(q, level, sort);
    }

    // GET /api/scan/5
    @GetMapping("/scan/{id}")
    public ResponseEntity<?> getOne(@PathVariable Long id) {
        return phishService.findById(id)
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElse(notFound(id));
    }

    // DELETE /api/scan/5
    @DeleteMapping("/scan/{id}")
    public ResponseEntity<?> deleteOne(@PathVariable Long id) {
        return phishService.delete(id) ? ResponseEntity.noContent().build() : notFound(id);
    }

    // DELETE /api/scan/history   (clears everything)
    @DeleteMapping("/scan/history")
    public ResponseEntity<Void> clearHistory() {
        phishService.deleteAll();
        return ResponseEntity.noContent().build();
    }

    // GET /api/dashboard/stats
    @GetMapping("/dashboard/stats")
    public Map<String, Object> stats() {
        return phishService.getStats();
    }

    // ---- Error handling: invalid input -> 400 with a clear message ----
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadInput(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }

    private ResponseEntity<Map<String, String>> notFound(Long id) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", "Scan " + id + " not found."));
    }
}