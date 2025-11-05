package com.example.ssoapp.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "sso_config")
public class SsoConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String ssoType;
    private Boolean enabled;
    private String configUrl; // Used for SAML Metadata URL or OIDC issuer URL

    // NEW FIELDS ADDED HERE
    private String verificationCertificate; // For IdP certificate
    private String signingKey;              // For SP signing key

    // Test result fields (not directly related to the fix, but included for completeness)
    private String lastAssertion;
    private String lastTestStatus;

    // Default constructor for JPA
    public SsoConfig() {
    }

    public SsoConfig(String ssoType, Boolean enabled) {
        this.ssoType = ssoType;
        this.enabled = enabled;
    }

    // --- Getters and Setters ---

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSsoType() {
        return ssoType;
    }

    public void setSsoType(String ssoType) {
        this.ssoType = ssoType;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public String getConfigUrl() {
        return configUrl;
    }

    public void setConfigUrl(String configUrl) {
        this.configUrl = configUrl;
    }

    // NEW GETTERS AND SETTERS ADDED HERE
    public String getVerificationCertificate() {
        return verificationCertificate;
    }

    public void setVerificationCertificate(String verificationCertificate) {
        this.verificationCertificate = verificationCertificate;
    }

    public String getSigningKey() {
        return signingKey;
    }

    public void setSigningKey(String signingKey) {
        this.signingKey = signingKey;
    }

    public String getLastAssertion() {
        return lastAssertion;
    }

    public void setLastAssertion(String lastAssertion) {
        this.lastAssertion = lastAssertion;
    }

    public String getLastTestStatus() {
        return lastTestStatus;
    }

    public void setLastTestStatus(String lastTestStatus) {
        this.lastTestStatus = lastTestStatus;
    }
}