package com.example.ssoapp.config; // 👈 Note the 'config' package

import com.example.ssoapp.model.SsoConfig;
import com.example.ssoapp.service.SsoConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;

/**
 * Dynamically loads SAML 2.0 Relying Party configurations from the database.
 * This bean is automatically picked up by Spring Security's SAML infrastructure.
 */
@Component // 👈 This is critical
public class DynamicRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository, Iterable<RelyingPartyRegistration> {

    private static final Logger logger = LoggerFactory.getLogger(DynamicRelyingPartyRegistrationRepository.class);

    @Autowired
    private SsoConfigService ssoConfigService;

    // The registrationId we use in our app (from login.html and WebSecurityConfig)
    private static final String DEFAULT_REGISTRATION_ID = "miniorange-saml";

    /**
     * Finds a SAML configuration by its registrationId. This is called at login.
     */
    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        logger.debug("Attempting to find SAML config for registrationId: {}", registrationId);

        // Fetch the SAML config from the DB
        SsoConfig config = ssoConfigService.getSsoConfigByType("SAML");

        if (config == null || !config.getEnabled()) {
            logger.warn("SAML config is not found or is disabled in the database.");
            return null;
        }

        // Ensure the requested ID matches what we expect
        if (!registrationId.equals(this.getRegistrationId(config))) {
            logger.warn("Requested registrationId '{}' does not match configured SP Entity ID '{}'",
                    registrationId, this.getRegistrationId(config));
            return null;
        }

        return convertConfigToRegistration(config);
    }

    /**
     * Provides an iterator over all enabled SAML configurations.
     */
    @Override
    public Iterator<RelyingPartyRegistration> iterator() {
        return ssoConfigService.getAllSsoConfigs().stream()
                .filter(config -> "SAML".equals(config.getSsoType()) && config.getEnabled())
                .map(this::convertConfigToRegistration)
                .iterator();
    }

    /**
     * Helper method to convert our SsoConfig entity into a Spring Security
     * RelyingPartyRegistration object.
     */
    private RelyingPartyRegistration convertConfigToRegistration(SsoConfig config) {
        String registrationId = getRegistrationId(config);
        logger.info("Building dynamic SAML RelyingPartyRegistration for: {}", registrationId);

        try {
            // 1. Load the SAML signing certificate from the config text
            X509Certificate idpCertificate = parseCertificate(config.getIdpCertificateContent());

            // 2. Create the SAML credential
            Saml2X509Credential credential = Saml2X509Credential.verification(idpCertificate);

            // 3. Build the RelyingPartyRegistration
            return RelyingPartyRegistration.withRegistrationId(registrationId)
                    // Our (Service Provider) details
                    .entityId(config.getSpEntityId()) // Use SP Entity ID from DB
                    .assertionConsumerServiceLocation("{baseUrl}/login/saml2/sso/{registrationId}")

                    // Their (Identity Provider) details
                    .assertingPartyDetails(party -> party
                            .entityId(config.getIdpEntityId())
                            .singleSignOnServiceLocation(config.getIdpSsoUrl())
                            .verificationX509Credentials(c -> c.add(credential))
                            .wantAuthnRequestsSigned(false)
                    )
                    .build();

        } catch (Exception e) {
            logger.error("Failed to configure SAML provider '{}': {}. Check certificate and fields in database.",
                    registrationId, e.getMessage(), e);
            return null; // This provider will be disabled
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