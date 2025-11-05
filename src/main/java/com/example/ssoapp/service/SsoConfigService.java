package com.example.ssoapp.service;

import com.example.ssoapp.model.SsoConfig;
import com.example.ssoapp.repository.SsoConfigRepository;
import org.springframework.cache.annotation.Cacheable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.cache.annotation.CacheEvict;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class SsoConfigService {
    private static final Logger logger = LoggerFactory.getLogger(SsoConfigService.class);

    @Autowired
    private SsoConfigRepository ssoConfigRepository;
    private static final String DEFAULT_SP_ENTITY_ID = "ssoapp";

    // Hardcoded metadata URL to ensure it's set on initialization
    private static final String DEFAULT_SAML_METADATA_URL = "https://pratisha.xecurify.com/moas/metadata/saml/379428/432956";

    @Cacheable("ssoConfigs")
    public List<SsoConfig> getAllSsoConfigs() {
        return ssoConfigRepository.findAll();
    }

    public SsoConfig getSsoConfigByType(String ssoType) {
        return ssoConfigRepository.findBySsoType(ssoType)
                .orElseGet(() -> {
                    // Create default if not exists
                    logger.warn("No SsoConfig found for type '{}', creating a new default entry.", ssoType);
                    SsoConfig config = new SsoConfig(ssoType, true);

                    // FIX: If this is the SAML config, set the default URL
                    if ("SAML".equals(ssoType)) {
                        config.setConfigUrl(DEFAULT_SAML_METADATA_URL);
                        logger.info("Populating default SAML config with metadata URL: {}", DEFAULT_SAML_METADATA_URL);
                    }

                    return ssoConfigRepository.save(config);
                });
    }

    @Transactional
    @CacheEvict(value = "ssoConfigs", allEntries = true)
    public SsoConfig updateSsoConfig(String ssoType, Boolean enabled) {
        Optional<SsoConfig> existing = ssoConfigRepository.findBySsoType(ssoType);

        if (existing.isPresent()) {
            SsoConfig config = existing.get();
            config.setEnabled(enabled);
            logger.info("Updated SSO config for {}: enabled={}", ssoType, enabled);
            return ssoConfigRepository.save(config);
        } else {
            SsoConfig config = new SsoConfig(ssoType, enabled);
            logger.info("Created new SSO config for {}: enabled={}", ssoType, enabled);
            return ssoConfigRepository.save(config);
        }
    }

    @Transactional
    @CacheEvict(value = "ssoConfigs", allEntries = true)
    public void initializeDefaultConfigs() {
        // Initialize default configurations if they don't exist
        String[] ssoTypes = {"JWT", "OIDC", "SAML"};
        for (String ssoType : ssoTypes) {
            if (ssoConfigRepository.findBySsoType(ssoType).isEmpty()) {
                SsoConfig config = new SsoConfig(ssoType, true);

                // FIX: If this is the SAML config, set the default URL
                if ("SAML".equals(ssoType)) {
                    config.setConfigUrl(DEFAULT_SAML_METADATA_URL);
                    config.setSpEntityId(DEFAULT_SP_ENTITY_ID);
                    logger.info("Initializing default SAML config with metadata URL: {}", DEFAULT_SAML_METADATA_URL);
                } else {
                    logger.info("Initialized default SSO config for {}", ssoType);
                }
                ssoConfigRepository.save(config);
            }
        }
    }

    public boolean isSsoEnabled(String ssoType) {
        // Use findBySsoType which is cached friendly vs getSsoConfigByType which can write
        Optional<SsoConfig> config = ssoConfigRepository.findBySsoType(ssoType);
        return config.map(SsoConfig::getEnabled).orElse(true); // Default to true if not found
    }

    @Transactional
    public void storeTestResult(String ssoType, String assertion, String status) {
        Optional<SsoConfig> configOpt = ssoConfigRepository.findBySsoType(ssoType);
        if (configOpt.isPresent()) {
            SsoConfig config = configOpt.get();
            config.setLastAssertion(assertion);
            config.setLastTestStatus(status);
            ssoConfigRepository.save(config);
            logger.info("Stored test result for {}: status={}", ssoType, status);
        }
    }

    /**
     * Updates the configuration details for a specific SSO type.
     * This is how you can set the metadataUrl, certificate, etc., from your admin UI.
     * @param ssoType The type of SSO (e.g., "SAML")
     * @param details A map of configuration keys to update (e.g., "configUrl" -> "http://...")
     */
    @Transactional
    @CacheEvict(value = "ssoConfigs", allEntries = true)
    public SsoConfig updateSsoConfigDetails(String ssoType, Map<String, String> details) {
        SsoConfig config = ssoConfigRepository.findBySsoType(ssoType)
                .orElse(new SsoConfig(ssoType, true)); // Create if not exists

        if (details.containsKey("configUrl")) {
            config.setConfigUrl(details.get("configUrl"));
        }
        if (details.containsKey("verificationCertificate")) {
            config.setVerificationCertificate(details.get("verificationCertificate"));
        }
        if (details.containsKey("signingKey")) {
            config.setSigningKey(details.get("signingKey"));
        }

        logger.info("Updating configuration details for {}", ssoType);
        return ssoConfigRepository.save(config);
    }

    /**
     * Retrieves a single configuration value for a specific SSO type.
     * @param ssoType The type of SSO (e.g., "SAML")
     * @param key The configuration key (e.g., "configUrl")
     * @return The configuration value, or null if not found.
     */
    @Cacheable(value = "ssoConfigValue", key = "#ssoType + '-' + #key")
    public String getConfigValue(String ssoType, String key) {
        SsoConfig config = getSsoConfigByType(ssoType);

        switch (key) {
            case "configUrl":
                return config.getConfigUrl();
            case "verificationCertificate":
                return config.getVerificationCertificate();
            case "signingKey":
                return config.getSigningKey();
            default:
                logger.warn("Unknown config key '{}' requested for type '{}'", key, ssoType);
                return null;
        }
    }
}