package com.example.ssoapp.service;

import com.example.ssoapp.config.TenantContext;
import com.example.ssoapp.model.SsoConfig;
import com.example.ssoapp.repository.SsoConfigRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class SsoConfigService {
    private static final Logger logger = LoggerFactory.getLogger(SsoConfigService.class);

    private final SsoConfigRepository ssoConfigRepository;

    public SsoConfigService(SsoConfigRepository ssoConfigRepository) {
        this.ssoConfigRepository = ssoConfigRepository;
    }

    /**
     * Get SSO config for current tenant (or global if SuperAdmin)
     * Returns null if no tenant context or config not found
     */
    public SsoConfig getSsoConfigByType(String ssoType) {
        try {
            Long tenantId = TenantContext.getTenantIdAsLong();

            if (tenantId != null) {
                // Tenant-specific lookup
                logger.debug("Looking up {} SSO config for tenant: {}", ssoType, tenantId);
                return ssoConfigRepository.findByTenantIdAndSsoType(tenantId, ssoType)
                        .orElse(null);
            } else {
                // SuperAdmin context - no SSO configs
                logger.debug("SuperAdmin context - no SSO configs available");
                return null;
            }
        } catch (Exception e) {
            logger.error("Error fetching SSO config for type {}: {}", ssoType, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Check if SSO is enabled for current tenant
     */
    public boolean isSsoEnabled(String ssoType) {
        try {
            SsoConfig config = getSsoConfigByType(ssoType);
            return config != null && config.getEnabled();
        } catch (Exception e) {
            logger.error("Error checking if SSO is enabled: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Get all SSO configs for current tenant
     */
    public List<SsoConfig> getAllSsoConfigs() {
        try {
            Long tenantId = TenantContext.getTenantIdAsLong();

            if (tenantId != null) {
                return ssoConfigRepository.findByTenantId(tenantId);
            } else {
                // SuperAdmin - return empty list
                logger.debug("SuperAdmin context - returning empty SSO config list");
                return new ArrayList<>();
            }
        } catch (Exception e) {
            logger.error("Error fetching all SSO configs: {}", e.getMessage(), e);
            return new ArrayList<>();
        }
    }

    /**
     * Initialize default SSO configs for a new tenant
     */
    @Transactional
    public void initializeDefaultConfigsForTenant(Long tenantId) {
        try {
            logger.info("Initializing default SSO configs for tenant: {}", tenantId);

            String[] ssoTypes = {"JWT", "OIDC", "SAML"};
            for (String ssoType : ssoTypes) {
                Optional<SsoConfig> existing = ssoConfigRepository.findByTenantIdAndSsoType(tenantId, ssoType);

                if (existing.isEmpty()) {
                    SsoConfig config = new SsoConfig(tenantId, ssoType, false); // Disabled by default
                    ssoConfigRepository.save(config);
                    logger.info("Created default {} config for tenant {}", ssoType, tenantId);
                }
            }
        } catch (Exception e) {
            logger.error("Error initializing default SSO configs for tenant {}: {}", tenantId, e.getMessage(), e);
            throw new RuntimeException("Failed to initialize SSO configs", e);
        }
    }

    /**
     * Update SSO config for current tenant
     */
    @Transactional
    public SsoConfig updateSsoConfig(String ssoType, Boolean enabled) {
        Long tenantId = TenantContext.getTenantIdAsLong();

        if (tenantId == null) {
            throw new RuntimeException("Cannot update SSO config in SuperAdmin context");
        }

        Optional<SsoConfig> existing = ssoConfigRepository.findByTenantIdAndSsoType(tenantId, ssoType);

        if (existing.isPresent()) {
            SsoConfig config = existing.get();
            config.setEnabled(enabled);
            logger.info("Updated SSO config for tenant {}: {} enabled={}", tenantId, ssoType, enabled);
            return ssoConfigRepository.save(config);
        } else {
            SsoConfig config = new SsoConfig(tenantId, ssoType, enabled);
            logger.info("Created new SSO config for tenant {}: {} enabled={}", tenantId, ssoType, enabled);
            return ssoConfigRepository.save(config);
        }
    }

    /**
     * Update detailed SSO config
     */
    @Transactional
    public SsoConfig updateSsoConfigDetails(String ssoType, Map<String, String> details) {
        Long tenantId = TenantContext.getTenantIdAsLong();

        if (tenantId == null) {
            throw new RuntimeException("Cannot update SSO config in SuperAdmin context");
        }

        SsoConfig config = ssoConfigRepository.findByTenantIdAndSsoType(tenantId, ssoType)
                .orElse(new SsoConfig(tenantId, ssoType, true));

        logger.info("Updating configuration details for tenant {} - {}", tenantId, ssoType);

        // Update fields
        if (details.containsKey("configUrl")) config.setConfigUrl(details.get("configUrl"));
        if (details.containsKey("verificationCertificate")) config.setVerificationCertificate(details.get("verificationCertificate"));
        if (details.containsKey("signingKey")) config.setSigningKey(details.get("signingKey"));
        if (details.containsKey("clientId")) config.setClientId(details.get("clientId"));
        if (details.containsKey("clientSecret")) config.setClientSecret(details.get("clientSecret"));
        if (details.containsKey("issuerUri")) config.setIssuerUri(details.get("issuerUri"));
        if (details.containsKey("entityId")) config.setSpEntityId(details.get("entityId"));
        if (details.containsKey("idpEntityId")) config.setIdpEntityId(details.get("idpEntityId"));
        if (details.containsKey("ssoServiceUrl")) config.setIdpSsoUrl(details.get("ssoServiceUrl"));
        if (details.containsKey("idpCertificateContent")) config.setIdpCertificateContent(details.get("idpCertificateContent"));

        return ssoConfigRepository.save(config);
    }

    /**
     * Store test result
     */
    @Transactional
    public void storeTestResult(String ssoType, String assertion, String status) {
        try {
            Long tenantId = TenantContext.getTenantIdAsLong();
            if (tenantId != null) {
                Optional<SsoConfig> configOpt = ssoConfigRepository.findByTenantIdAndSsoType(tenantId, ssoType);
                if (configOpt.isPresent()) {
                    SsoConfig config = configOpt.get();
                    config.setLastAssertion(assertion);
                    config.setLastTestStatus(status);
                    ssoConfigRepository.save(config);
                    logger.info("Stored test result for tenant {} - {}: status={}", tenantId, ssoType, status);
                }
            }
        } catch (Exception e) {
            logger.error("Error storing test result: {}", e.getMessage(), e);
        }
    }
}