package com.phishguard.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** One saved scan -> one row in the scan_results table. */
@Entity
@Table(name = "scan_results")
public class ScanResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 2048)
    private String url;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Column(name = "risk_level", nullable = false, length = 10)
    private String riskLevel;            // LOW, MEDIUM, HIGH or CRITICAL

    // Issues are stored in one TEXT column, separated by "|"
    @Column(name = "issues", columnDefinition = "TEXT")
    private String issuesText;

    @Column(name = "scanned_at", nullable = false)
    private LocalDateTime scannedAt;

    // Not stored in the database; filled in when returning a result
    @Transient
    private String hostname;
    @Transient
    private boolean https;

    public ScanResult() { }

    // ---- JSON-friendly "issues" as a list ----
    public List<String> getIssues() {
        if (issuesText == null || issuesText.isBlank()) return Collections.emptyList();
        return Arrays.asList(issuesText.split("\\|"));
    }

    public void setIssues(List<String> issues) {
        this.issuesText = String.join("|", issues);
    }

    // Computed from the risk level, so it is never stored
    public String getRecommendation() {
        if (riskLevel == null) return "";
        return switch (riskLevel) {
            case "CRITICAL" -> "Do not open this link or enter any information. Report it as phishing.";
            case "HIGH" -> "Do not enter credentials on this website.";
            case "MEDIUM" -> "Be careful. Verify the sender and the real domain before continuing.";
            default -> "No major red flags found, but always stay alert.";
        };
    }

    public Long getId() { return id; }
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
    public LocalDateTime getScannedAt() { return scannedAt; }
    public void setScannedAt(LocalDateTime scannedAt) { this.scannedAt = scannedAt; }
    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }
    public boolean isHttps() { return https; }
    public void setHttps(boolean https) { this.https = https; }
}