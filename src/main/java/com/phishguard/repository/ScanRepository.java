package com.phishguard.repository;

import com.phishguard.model.ScanResult;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ScanRepository extends JpaRepository<ScanResult, Long> {

    // Search + filter. Empty string means "no filter".
    // Parameters are bound by JPA, so this is safe from SQL injection.
    @Query("SELECT s FROM ScanResult s " +
           "WHERE LOWER(s.url) LIKE LOWER(CONCAT('%', :q, '%')) " +
           "AND (:level = '' OR s.riskLevel = :level)")
    List<ScanResult> search(@Param("q") String q, @Param("level") String level, Sort sort);

    long countByRiskLevel(String riskLevel);

    List<ScanResult> findTop5ByOrderByScannedAtDesc();

    List<ScanResult> findTop5ByOrderByRiskScoreDesc();
}