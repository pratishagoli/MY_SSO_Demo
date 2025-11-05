package com.example.ssoapp.repository;

import com.example.ssoapp.model.SsoConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SsoConfigRepository extends JpaRepository<SsoConfig, Long> {
    Optional<SsoConfig> findBySsoType(String ssoType);
}

