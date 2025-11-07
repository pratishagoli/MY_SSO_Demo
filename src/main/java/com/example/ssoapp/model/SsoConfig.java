package com.example.ssoapp.model;

import jakarta.persistence.*;

@Entity
@Table(name = "sso_config")
public class SsoConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 🚀 NEW: Make SSO config tenant-specific
    @Column(name = "tenant_id", nullable = true)
    private Long tenantId; // NULL = global/superadmin config, NOT NULL = tenant-specific

    private String ssoType;
    private Boolean enabled;
    private String configUrl;

    // ... rest of existing fields ...
    private String verificationCertificate;
    private String signingKey;
    private String lastAssertion;
    private String lastTestStatus;

    @Column(length = 1000)
    private String idpEntityId;

    @Column(length = 1000)
    private String idpSsoUrl;

    @Column(columnDefinition = "TEXT")
    private String idpCertificateContent;

    @Column(length = 1000)
    private String spEntityId;

    @Column(length = 255)
    private String clientId;

    @Column(length = 255)
    private String clientSecret;

    @Column(length = 1000)
    private String issuerUri;

    // Constructors
    public SsoConfig() {}

    public SsoConfig(String ssoType, Boolean enabled) {
        this.ssoType = ssoType;
        this.enabled = enabled;
    }

    // 🚀 NEW: Constructor with tenant
    public SsoConfig(Long tenantId, String ssoType, Boolean enabled) {
        this.tenantId = tenantId;
        this.ssoType = ssoType;
        this.enabled = enabled;
    }

    // Getters and Setters (ADD THIS NEW ONE)

    public Long getTenantId() {
        return tenantId;
    }

    public void setTenantId(Long tenantId) {
        this.tenantId = tenantId;
    }

    // ... rest of your existing getters/setters remain the same ...

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getSsoType() { return ssoType; }
    public void setSsoType(String ssoType) { this.ssoType = ssoType; }

    public Boolean getEnabled() { return enabled; }
    public void setEnabled(Boolean enabled) { this.enabled = enabled; }

    public String getConfigUrl() { return configUrl; }
    public void setConfigUrl(String configUrl) { this.configUrl = configUrl; }

    public String getVerificationCertificate() { return verificationCertificate; }
    public void setVerificationCertificate(String verificationCertificate) {
        this.verificationCertificate = verificationCertificate;
    }

    public String getSigningKey() { return signingKey; }
    public void setSigningKey(String signingKey) { this.signingKey = signingKey; }

    public String getLastAssertion() { return lastAssertion; }
    public void setLastAssertion(String lastAssertion) { this.lastAssertion = lastAssertion; }

    public String getLastTestStatus() { return lastTestStatus; }
    public void setLastTestStatus(String lastTestStatus) { this.lastTestStatus = lastTestStatus; }

    public String getIdpEntityId() { return idpEntityId; }
    public void setIdpEntityId(String idpEntityId) { this.idpEntityId = idpEntityId; }

    public String getIdpSsoUrl() { return idpSsoUrl; }
    public void setIdpSsoUrl(String idpSsoUrl) { this.idpSsoUrl = idpSsoUrl; }

    public String getIdpCertificateContent() { return idpCertificateContent; }
    public void setIdpCertificateContent(String idpCertificateContent) {
        this.idpCertificateContent = idpCertificateContent;
    }

    public String getSpEntityId() { return spEntityId; }
    public void setSpEntityId(String spEntityId) { this.spEntityId = spEntityId; }

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

    public String getIssuerUri() { return issuerUri; }
    public void setIssuerUri(String issuerUri) { this.issuerUri = issuerUri; }
}