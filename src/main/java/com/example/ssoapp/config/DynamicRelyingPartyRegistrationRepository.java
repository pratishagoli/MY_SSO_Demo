package com.example.ssoapp.config;

import com.example.ssoapp.model.SsoConfig;
import com.example.ssoapp.service.SsoConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Dynamically loads SAML 2.0 Relying Party configurations from the database.
 * This bean is automatically picked up by Spring Security's SAML infrastructure.
 *
 * FIXED: Removed @Autowired to avoid circular dependency issues
 */
@Component
public class DynamicRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository, Iterable<RelyingPartyRegistration> {

    private static final Logger logger = LoggerFactory.getLogger(DynamicRelyingPartyRegistrationRepository.class);

    private final SsoConfigService ssoConfigService;

    // The registrationId we use in our app (from login.html and WebSecurityConfig)
    private static final String DEFAULT_REGISTRATION_ID = "miniorange-saml";

    // Constructor injection instead of field injection
    public DynamicRelyingPartyRegistrationRepository(SsoConfigService ssoConfigService) {
        this.ssoConfigService = ssoConfigService;
        logger.info("✅ DynamicRelyingPartyRegistrationRepository initialized");
    }

    /**
     * Finds a SAML configuration by its registrationId. This is called at login.
     */
    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        logger.debug("Attempting to find SAML config for registrationId: {}", registrationId);

        try {
            // Fetch the SAML config from the DB
            SsoConfig config = ssoConfigService.getSsoConfigByType("SAML");

            if (config == null) {
                logger.warn("SAML config is not found in the database for current tenant");
                return null;
            }

            if (!config.getEnabled()) {
                logger.warn("SAML config is disabled in the database");
                return null;
            }

            // Ensure the requested ID matches what we expect
            String expectedId = getRegistrationId(config);
            if (!registrationId.equals(expectedId)) {
                logger.warn("Requested registrationId '{}' does not match configured SP Entity ID '{}'",
                        registrationId, expectedId);
                return null;
            }

            return convertConfigToRegistration(config);
        } catch (Exception e) {
            logger.error("Error fetching SAML configuration: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Provides an iterator over all enabled SAML configurations.
     */
    @Override
    public Iterator<RelyingPartyRegistration> iterator() {
        try {
            List<RelyingPartyRegistration> registrations = new ArrayList<>();

            List<SsoConfig> configs = ssoConfigService.getAllSsoConfigs();

            for (SsoConfig config : configs) {
                if ("SAML".equals(config.getSsoType()) && config.getEnabled()) {
                    RelyingPartyRegistration registration = convertConfigToRegistration(config);
                    if (registration != null) {
                        registrations.add(registration);
                    }
                }
            }

            return registrations.iterator();
        } catch (Exception e) {
            logger.error("Error iterating SAML configurations: {}", e.getMessage(), e);
            return new ArrayList<RelyingPartyRegistration>().iterator();
        }
    }

    /**
     * Helper method to convert our SsoConfig entity into a Spring Security
     * RelyingPartyRegistration object.
     */
    private RelyingPartyRegistration convertConfigToRegistration(SsoConfig config) {
        String registrationId = getRegistrationId(config);
        logger.info("Building dynamic SAML RelyingPartyRegistration for: {}", registrationId);

        try {
            // Validate required fields
            if (config.getSpEntityId() == null || config.getSpEntityId().trim().isEmpty()) {
                logger.error("SAML config missing SP Entity ID");
                return null;
            }

            if (config.getIdpEntityId() == null || config.getIdpEntityId().trim().isEmpty()) {
                logger.error("SAML config missing IDP Entity ID");
                return null;
            }

            if (config.getIdpSsoUrl() == null || config.getIdpSsoUrl().trim().isEmpty()) {
                logger.error("SAML config missing IDP SSO URL");
                return null;
            }

            if (config.getIdpCertificateContent() == null || config.getIdpCertificateContent().trim().isEmpty()) {
                logger.error("SAML config missing IDP Certificate");
                return null;
            }

            // 1. Load the SAML signing certificate from the config text
            X509Certificate idpCertificate = parseCertificate(config.getIdpCertificateContent());

            // 2. Create the SAML credential
            Saml2X509Credential credential = Saml2X509Credential.verification(idpCertificate);

            // 3. Build the RelyingPartyRegistration
            return RelyingPartyRegistration.withRegistrationId(registrationId)
                    // Our (Service Provider) details
                    .entityId(config.getSpEntityId().trim())
                    .assertionConsumerServiceLocation("{baseUrl}/login/saml2/sso/{registrationId}")

                    // Their (Identity Provider) details
                    .assertingPartyDetails(party -> party
                            .entityId(config.getIdpEntityId().trim())
                            .singleSignOnServiceLocation(config.getIdpSsoUrl().trim())
                            .verificationX509Credentials(c -> c.add(credential))
                            .wantAuthnRequestsSigned(false)
                    )
                    .build();

        } catch (Exception e) {
            logger.error("Failed to configure SAML provider '{}': {}. Check certificate and fields in database.",
                    registrationId, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Converts a PEM certificate string (from DB) into an X509Certificate object.
     */
    private X509Certificate parseCertificate(String pemCertificate) throws Exception {
        if (pemCertificate == null || pemCertificate.isBlank()) {
            throw new IllegalArgumentException("SAML certificate content (idpCertificateContent) is null or empty in sso_config table.");
        }

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        String cleanPem = pemCertificate.trim();
        byte[] certificateBytes = cleanPem.getBytes(StandardCharsets.UTF_8);

        try (InputStream certStream = new ByteArrayInputStream(certificateBytes)) {
            return (X509Certificate) factory.generateCertificate(certStream);
        }
    }

    /**
     * Helper to determine the registrationId to use.
     * We get it from the SP Entity ID.
     */
    private String getRegistrationId(SsoConfig config) {
        if (config.getSpEntityId() != null && config.getSpEntityId().contains("/")) {
            String[] parts = config.getSpEntityId().split("/");
            if (parts.length > 0) {
                return parts[parts.length - 1]; // Use last part, e.g., "miniorange-saml"
            }
        }
        // Fallback to the one defined in your original WebSecurityConfig
        return DEFAULT_REGISTRATION_ID;
    }
}