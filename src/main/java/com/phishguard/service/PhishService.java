package com.phishguard.service;

import com.phishguard.model.ScanResult;
import com.phishguard.repository.ScanRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;

@Service
public class PhishService {

    private static final int MAX_URL_LENGTH = 2048;
    private static final int LONG_URL_LIMIT = 75;

    private static final List<String> KEYWORDS = List.of(
            "login", "verify", "verification", "account", "secure",
            "update", "password", "banking", "signin", "confirm");

    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
            "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click",
            "zip", "work", "support", "loan", "country", "buzz");

    private static final List<String> BRANDS = List.of(
            "paypal", "google", "microsoft", "apple", "amazon", "facebook",
            "netflix", "instagram", "whatsapp", "sbi", "hdfc", "icici");

    // e.g. "paypal.com.evil.xyz" tries to look like paypal.com
    private static final Set<String> TLD_WORDS = Set.of("com", "net", "org", "gov", "edu");
    // second-level labels used with country codes, e.g. example.co.in
    private static final Set<String> SECOND_LEVELS = Set.of("co", "com", "org", "net", "gov", "ac", "edu");

    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$");
    private static final Pattern ENCODED = Pattern.compile("%[0-9a-fA-F]{2}");
    private static final Pattern BAD_CHARS = Pattern.compile("[<>\"'`{}|\\\\^\\s]");

    private final ScanRepository scanRepository;

    // ---- Scoring points, read from application.properties ----
    @Value("${phishguard.score.no-https:15}") private int ptsNoHttps;
    @Value("${phishguard.score.ip-address:25}") private int ptsIp;
    @Value("${phishguard.score.long-url:10}") private int ptsLongUrl;
    @Value("${phishguard.score.many-subdomains:10}") private int ptsSubdomains;
    @Value("${phishguard.score.suspicious-chars:10}") private int ptsBadChars;
    @Value("${phishguard.score.at-symbol:20}") private int ptsAt;
    @Value("${phishguard.score.many-hyphens:10}") private int ptsHyphens;
    @Value("${phishguard.score.encoded-chars:10}") private int ptsEncoded;
    @Value("${phishguard.score.keyword:10}") private int ptsKeyword;
    @Value("${phishguard.score.suspicious-domain:10}") private int ptsDomain;
    @Value("${phishguard.score.misleading-domain:15}") private int ptsMisleading;
    @Value("${phishguard.score.port:10}") private int ptsPort;
    @Value("${phishguard.score.many-params:5}") private int ptsParams;
    @Value("${phishguard.score.suspicious-tld:15}") private int ptsTld;

    @Value("${phishguard.level.medium:30}") private int mediumFrom;
    @Value("${phishguard.level.high:60}") private int highFrom;
    @Value("${phishguard.level.critical:80}") private int criticalFrom;

    public PhishService(ScanRepository scanRepository) {
        this.scanRepository = scanRepository;
    }

    /** Small helper that collects points and explanations. */
    private static class Tally {
        int score = 0;
        final List<String> issues = new ArrayList<>();

        void add(String message, int points) {
            score += points;
            issues.add(message + " (+" + points + ")");
        }
    }

    // =====================================================================
    //  SCAN
    // =====================================================================
    public ScanResult scan(String rawUrl) {
        String url = validate(rawUrl);
        URL parsed = parse(url);          // static parsing only, no network access
        Tally tally = analyze(url, parsed);

        int score = Math.min(100, tally.score);   // cap at 100

        ScanResult result = new ScanResult();
        result.setUrl(url);
        result.setRiskScore(score);
        result.setRiskLevel(levelFor(score));
        result.setIssues(tally.issues);
        result.setScannedAt(LocalDateTime.now());

        ScanResult saved = scanRepository.save(result);
        fillDetails(saved);
        return saved;
    }

    /** Input validation: empty, too long, missing scheme. */
    private String validate(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            throw new IllegalArgumentException("URL must not be empty.");
        }
        String url = rawUrl.trim();
        if (url.length() > MAX_URL_LENGTH) {
            throw new IllegalArgumentException("URL is too long (maximum " + MAX_URL_LENGTH + " characters).");
        }
        if (!url.contains("://")) {
            url = "http://" + url;      // user typed "example.com/login"
        }
        String lower = url.toLowerCase();
        if (!lower.startsWith("http://") && !lower.startsWith("https://")) {
            throw new IllegalArgumentException("Only http:// and https:// URLs can be analyzed.");
        }
        return url;
    }

    /**
     * java.net.URL is used ONLY to split the string into parts (host, port, query).
     * We never call openConnection()/openStream(), so no request is ever sent.
     */
    private URL parse(String url) {
        try {
            URL parsed = new URL(url);
            if (parsed.getHost() == null || parsed.getHost().isBlank()) {
                throw new IllegalArgumentException("Could not find a hostname in the URL.");
            }
            return parsed;
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Malformed URL.");
        }
    }

    // =====================================================================
    //  THE 14 HEURISTIC CHECKS
    // =====================================================================
    private Tally analyze(String url, URL parsed) {
        Tally t = new Tally();
        String host = parsed.getHost().toLowerCase();
        String lowerUrl = url.toLowerCase();
        String[] labels = host.split("\\.");
        boolean isIp = IPV4.matcher(host).matches() || host.startsWith("[");

        // 1. HTTPS
        if (!parsed.getProtocol().equalsIgnoreCase("https")) {
            t.add("URL does not use HTTPS", ptsNoHttps);
        }

        // 2. Hostname is an IP address
        if (isIp) {
            t.add("Hostname is an IP address", ptsIp);
        }

        // 3. URL length
        if (url.length() > LONG_URL_LIMIT) {
            t.add("URL is very long (" + url.length() + " characters)", ptsLongUrl);
        }

        // 4. Number of subdomains (labels before the registered domain)
        int registeredIdx = registeredLabelIndex(labels);
        int subdomainCount = isIp ? 0 : registeredIdx;
        if (subdomainCount > 2) {
            t.add("Excessive subdomains (" + subdomainCount + ")", ptsSubdomains);
        }

        // 5. Suspicious characters in the URL or hostname
        boolean badHost = !isIp && !host.matches("[a-z0-9.\\-]+");
        if (BAD_CHARS.matcher(url).find() || badHost) {
            t.add("Suspicious characters found in the URL", ptsBadChars);
        }

        // 6. '@' symbol (browsers ignore everything before it)
        if (url.contains("@")) {
            t.add("URL contains an '@' symbol", ptsAt);
        }

        // 7. Excessive hyphens in the hostname
        long hyphens = host.chars().filter(c -> c == '-').count();
        if (hyphens >= 3) {
            t.add("Hostname contains many hyphens (" + hyphens + ")", ptsHyphens);
        }

        // 8. Encoded characters like %20 or %2F
        if (ENCODED.matcher(url).find()) {
            t.add("URL contains percent-encoded characters", ptsEncoded);
        }

        // 9. Suspicious keywords (counted once, all matches listed)
        List<String> found = new ArrayList<>();
        for (String keyword : KEYWORDS) {
            if (lowerUrl.contains(keyword)) found.add(keyword);
        }
        if (!found.isEmpty()) {
            t.add("Suspicious keywords detected: " + String.join(", ", found), ptsKeyword);
        }

        // 10. Suspicious-looking domain
        if (!isIp) {
            long digits = host.chars().filter(Character::isDigit).count();
            if (host.contains("xn--") || host.length() > 30 || digits >= 4) {
                t.add("Domain looks suspicious (punycode, very long or many digits)", ptsDomain);
            }
        }

        // 11. Misleading domain structure
        if (!isIp && isMisleading(labels, registeredIdx)) {
            t.add("Misleading domain structure (trusted name used in a fake position)", ptsMisleading);
        }

        // 12. Port in the hostname
        int port = parsed.getPort();
        if (port != -1 && port != 80 && port != 443) {
            t.add("URL uses a non-standard port (" + port + ")", ptsPort);
        }

        // 13. Number of query parameters
        String query = parsed.getQuery();
        int paramCount = (query == null || query.isEmpty()) ? 0 : query.split("&").length;
        if (paramCount > 4) {
            t.add("Many URL parameters (" + paramCount + ")", ptsParams);
        }

        // 14. Suspicious TLD
        if (!isIp && SUSPICIOUS_TLDS.contains(labels[labels.length - 1])) {
            t.add("Suspicious top-level domain (." + labels[labels.length - 1] + ")", ptsTld);
        }

        return t;
    }

    /** Index of the "main" label, e.g. example in www.example.com or example.co.in. */
    private int registeredLabelIndex(String[] labels) {
        int last = labels.length - 1;
        if (labels.length >= 3 && labels[last].length() == 2 && SECOND_LEVELS.contains(labels[last - 1])) {
            return labels.length - 3;
        }
        return Math.max(0, labels.length - 2);
    }

    /**
     * Two simple patterns:
     *  - paypal.com.evil.xyz  -> "com" appears before the real domain
     *  - login.paypal-help.xyz -> brand name in the host but not the real domain
     */
    private boolean isMisleading(String[] labels, int registeredIdx) {
        for (int i = 0; i < registeredIdx; i++) {
            if (TLD_WORDS.contains(labels[i])) return true;
        }
        String registeredLabel = labels[registeredIdx];
        String[] tokens = String.join(".", labels).split("[.\\-]");
        for (String brand : BRANDS) {
            boolean brandInHost = Arrays.asList(tokens).contains(brand);
            if (brandInHost && !registeredLabel.equals(brand)) return true;
        }
        return false;
    }

    private String levelFor(int score) {
        if (score >= criticalFrom) return "CRITICAL";
        if (score >= highFrom) return "HIGH";
        if (score >= mediumFrom) return "MEDIUM";
        return "LOW";
    }

    /** Fills the non-stored fields (hostname, https) from the saved URL. */
    private void fillDetails(ScanResult r) {
        try {
            URL parsed = new URL(r.getUrl());
            r.setHostname(parsed.getHost());
            r.setHttps(parsed.getProtocol().equalsIgnoreCase("https"));
        } catch (MalformedURLException ignored) {
            // URL was validated before saving, so this should not happen
        }
    }

    // =====================================================================
    //  HISTORY
    // =====================================================================
    public List<ScanResult> getHistory(String search, String level, String sortDir) {
        String q = (search == null) ? "" : search.trim();
        String lvl = (level == null) ? "" : level.trim().toUpperCase();
        if (!List.of("LOW", "MEDIUM", "HIGH", "CRITICAL").contains(lvl)) lvl = "";

        Sort.Direction dir = "asc".equalsIgnoreCase(sortDir) ? Sort.Direction.ASC : Sort.Direction.DESC;
        return scanRepository.search(q, lvl, Sort.by(dir, "scannedAt"));
    }

    public Optional<ScanResult> findById(Long id) {
        Optional<ScanResult> result = scanRepository.findById(id);
        result.ifPresent(this::fillDetails);
        return result;
    }

    public boolean delete(Long id) {
        if (!scanRepository.existsById(id)) return false;
        scanRepository.deleteById(id);
        return true;
    }

    public void deleteAll() {
        scanRepository.deleteAll();
    }

    // =====================================================================
    //  DASHBOARD STATS
    // =====================================================================
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("total", scanRepository.count());
        stats.put("low", scanRepository.countByRiskLevel("LOW"));
        stats.put("medium", scanRepository.countByRiskLevel("MEDIUM"));
        stats.put("high", scanRepository.countByRiskLevel("HIGH"));
        stats.put("critical", scanRepository.countByRiskLevel("CRITICAL"));
        stats.put("recent", scanRepository.findTop5ByOrderByScannedAtDesc());
        stats.put("highest", scanRepository.findTop5ByOrderByRiskScoreDesc());
        return stats;
    }
}