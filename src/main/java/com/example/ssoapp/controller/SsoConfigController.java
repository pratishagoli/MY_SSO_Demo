package com.example.ssoapp.controller;

import com.example.ssoapp.config.TenantContext;
import com.example.ssoapp.model.SsoConfig;
import com.example.ssoapp.service.SsoConfigService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller
@RequestMapping("/admin/sso")
public class SsoConfigController {

    private static final Logger logger = LoggerFactory.getLogger(SsoConfigController.class);

    @Autowired
    private SsoConfigService ssoConfigService;

    @GetMapping("/config")
    @PreAuthorize("hasAnyAuthority('ROLE_TENANT_ADMIN', 'ROLE_SUPERADMIN')")
    public String ssoConfigPage(Model model) {
        logger.info("=== SSO Config page accessed ===");

        Long tenantId = TenantContext.getTenantIdAsLong();
        logger.info("Current tenant context: {}", tenantId);

        List<SsoConfig> configs = new ArrayList<>();

        try {
            // Fetch existing configs
            configs = ssoConfigService.getAllSsoConfigs();
            logger.info("Fetched {} SSO configs from service", configs != null ? configs.size() : 0);

            // ✅ FIXED: Only initialize if NO configs exist at all
            if (configs == null || configs.isEmpty()) {
                logger.info("No SSO configs found, attempting to initialize defaults");

                // Only initialize if we have a tenant context
                if (tenantId != null) {
                    try {
                        logger.info("Initializing default SSO configs for tenant: {}", tenantId);
                        ssoConfigService.initializeDefaultConfigsForTenant(tenantId);

                        // Fetch again after initialization
                        configs = ssoConfigService.getAllSsoConfigs();
                        logger.info("After initialization, fetched {} configs", configs != null ? configs.size() : 0);
                    } catch (Exception e) {
                        logger.error("Failed to initialize SSO configs for tenant {}: {}", tenantId, e.getMessage(), e);
                        // Continue with empty list
                        configs = new ArrayList<>();
                    }
                } else {
                    logger.warn("Cannot initialize SSO configs without tenant context");
                    configs = new ArrayList<>();
                }
            } else {
                logger.info("Found {} existing SSO configs for tenant {}", configs.size(), tenantId);

                // Log each config for debugging
                for (SsoConfig config : configs) {
                    logger.info("  - Config: type={}, enabled={}, tenantId={}",
                            config.getSsoType(), config.getEnabled(), config.getTenantId());
                }
            }
        } catch (Exception e) {
            logger.error("Error loading SSO configs: {}", e.getMessage(), e);
            configs = new ArrayList<>();
        }

        // Always add the list to model, even if empty
        model.addAttribute("ssoConfigs", configs);
        logger.info("Added {} configs to model", configs.size());

        return "ssoconfig";
    }

    @PutMapping("/config/{ssoType}")
    @PreAuthorize("hasAnyAuthority('ROLE_TENANT_ADMIN', 'ROLE_SUPERADMIN')")
    @ResponseBody
    public ResponseEntity<?> updateSsoConfig(@PathVariable String ssoType, @RequestBody Map<String, Boolean> request) {
        try {
            Boolean enabled = request.get("enabled");
            if (enabled == null) {
                return ResponseEntity.badRequest().body("Missing 'enabled' field");
            }

            SsoConfig updated = ssoConfigService.updateSsoConfig(ssoType.toUpperCase(), enabled);
            return ResponseEntity.ok(updated);
        } catch (Exception e) {
            logger.error("Error updating SSO config: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to update SSO config: " + e.getMessage());
        }
    }

    @GetMapping("/config/{ssoType}/details")
    @PreAuthorize("hasAnyAuthority('ROLE_TENANT_ADMIN', 'ROLE_SUPERADMIN')")
    @ResponseBody
    public ResponseEntity<Map<String, String>> getSsoConfigDetails(@PathVariable String ssoType) {
        String type = ssoType.toUpperCase();
        SsoConfig config = ssoConfigService.getSsoConfigByType(type);

        if (config == null) {
            logger.warn("No config found for type: {}", type);
            return ResponseEntity.notFound().build();
        }

        Map<String, String> configMap = new HashMap<>();

        // Common properties
        configMap.put("ssoType", type);
        configMap.put("status", config.getEnabled() ? "Enabled" : "Disabled");
        configMap.put("provider", "MiniOrange");

        // Read properties from database
        switch (type) {
            case "JWT":
                configMap.put("protocol", "JWT (JSON Web Token)");
                configMap.put("clientId", config.getClientId() != null ? config.getClientId() : "");
                configMap.put("issuerUri", config.getIssuerUri() != null ? config.getIssuerUri() : "");
                configMap.put("redirectUri", "http://localhost:8080/auth/jwt/callback");
                configMap.put("loginUrl", "https://pratisha.xecurify.com/moas/idp/jwtsso/379428");
                break;
            case "OIDC":
                configMap.put("protocol", "OIDC (OpenID Connect)");
                configMap.put("clientId", config.getClientId() != null ? config.getClientId() : "");
                configMap.put("clientSecret", config.getClientSecret() != null ? config.getClientSecret() : "");
                configMap.put("scope", "openid,profile,email");
                configMap.put("issuerUri", config.getIssuerUri() != null ? config.getIssuerUri() : "");
                configMap.put("grantType", "authorization_code");
                configMap.put("redirectUri", "http://localhost:8080/login/oauth2/code/miniorange");
                break;
            case "SAML":
                configMap.put("protocol", "SAML 2.0");
                configMap.put("entityId", config.getSpEntityId() != null ? config.getSpEntityId() : "");
                configMap.put("metadataUrl", config.getConfigUrl() != null ? config.getConfigUrl() : "");
                configMap.put("ssoServiceUrl", config.getIdpSsoUrl() != null ? config.getIdpSsoUrl() : "");
                configMap.put("idpEntityId", config.getIdpEntityId() != null ? config.getIdpEntityId() : "");
                configMap.put("idpCertificateContent", config.getIdpCertificateContent() != null ? config.getIdpCertificateContent() : "");
                configMap.put("acsUrl", "http://localhost:8080/login/saml2/sso/miniorange-saml");
                configMap.put("nameIdFormat", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
                break;
            default:
                return ResponseEntity.badRequest().build();
        }

        return ResponseEntity.ok(configMap);
    }

    @PutMapping("/config/{ssoType}/update")
    @PreAuthorize("hasAnyAuthority('ROLE_TENANT_ADMIN', 'ROLE_SUPERADMIN')")
    @ResponseBody
    public ResponseEntity<?> updateSsoConfigDetails(@PathVariable String ssoType, @RequestBody Map<String, String> details) {
        try {
            SsoConfig updatedConfig = ssoConfigService.updateSsoConfigDetails(ssoType.toUpperCase(), details);
            return ResponseEntity.ok(updatedConfig);
        } catch (Exception e) {
            logger.error("Failed to update config details for {}: {}", ssoType, e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to update configuration: " + e.getMessage());
        }
    }

    // Rest of your methods remain the same...
    @GetMapping("/test/{ssoType}")
    @PreAuthorize("hasAnyAuthority('ROLE_TENANT_ADMIN', 'ROLE_SUPERADMIN')")
    public String testSso(@PathVariable String ssoType, jakarta.servlet.http.HttpServletRequest request) {
        String type = ssoType.toUpperCase();

        storeAdminSession(request);
        request.getSession().setAttribute("sso_test_mode", true);
        request.getSession().setAttribute("sso_test_type", type);

        switch (type) {
            case "JWT":
                return "redirect:https://pratisha.xecurify.com/moas/idp/jwtsso/379428?client_id=4rIAZPjSTgKGuylgQvCNenKqZRkHOC6f&redirect_uri=http://localhost:8080/auth/jwt/callback";
            case "OIDC":
                return "redirect:/oauth2/authorization/miniorange";
            case "SAML":
                return "redirect:/saml2/authenticate/miniorange-saml";
            default:
                return "redirect:/admin/sso/config?error=invalid_sso_type";
        }
    }

    @GetMapping("/test/jwt/callback")
    public String jwtTestCallback(@RequestParam("id_token") String jwt, jakarta.servlet.http.HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response) throws java.io.IOException {
        Map<String, Object> testResult = new HashMap<>();
        Map<String, Object> attributes = new HashMap<>();
        String testStatus = "success";

        try {
            String[] parts = jwt.split("\\.");
            if (parts.length >= 2) {
                String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
                ObjectMapper mapper = new ObjectMapper();
                attributes = mapper.readValue(payload, Map.class);
            }
        } catch (Exception e) {
            testStatus = "error";
            attributes.put("error", "Failed to decode JWT: " + e.getMessage());
        }

        testResult.put("testType", "JWT");
        testResult.put("token", jwt);
        testResult.put("testStatus", testStatus);
        testResult.put("attributes", attributes);

        request.getSession().setAttribute("sso_test_result", testResult);
        restoreAdminSession(request);

        response.sendRedirect("/admin/sso/config?test=success");
        return null;
    }

    @GetMapping("/test/result")
    @ResponseBody
    @PreAuthorize("hasAnyAuthority('ROLE_TENANT_ADMIN', 'ROLE_SUPERADMIN')")
    public ResponseEntity<Map<String, Object>> getTestResult(jakarta.servlet.http.HttpServletRequest request) {
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) request.getSession().getAttribute("sso_test_result");
        if (result != null) {
            String assertionJson = (String) request.getSession().getAttribute("saml_assertion_to_store");
            if (assertionJson != null && "SAML".equals(result.get("testType"))) {
                String status = (String) result.get("testStatus");
                ssoConfigService.storeTestResult("SAML", assertionJson, status);
                request.getSession().removeAttribute("saml_assertion_to_store");
            }

            request.getSession().removeAttribute("sso_test_result");
            return ResponseEntity.ok(result);
        }
        return ResponseEntity.ok(new HashMap<>());
    }

    private void storeAdminSession(jakarta.servlet.http.HttpServletRequest request) {
        org.springframework.security.core.Authentication auth =
                org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            request.getSession().setAttribute("admin_test_principal", auth);
            request.getSession().setAttribute("admin_test_authorities", auth.getAuthorities());
        }
    }

    private void restoreAdminSession(jakarta.servlet.http.HttpServletRequest request) {
        org.springframework.security.core.Authentication adminAuth =
                (org.springframework.security.core.Authentication) request.getSession().getAttribute("admin_test_principal");
        if (adminAuth != null) {
            org.springframework.security.core.context.SecurityContext securityContext =
                    org.springframework.security.core.context.SecurityContextHolder.getContext();
            securityContext.setAuthentication(adminAuth);

            jakarta.servlet.http.HttpSession session = request.getSession();
            session.setAttribute(
                    org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                    securityContext
            );

            request.getSession().removeAttribute("admin_test_principal");
            request.getSession().removeAttribute("admin_test_authorities");
        }
    }
}