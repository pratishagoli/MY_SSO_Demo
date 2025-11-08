package com.example.ssoapp.controller;

import com.example.ssoapp.config.TenantContext;
import com.example.ssoapp.model.SsoConfig;
import com.example.ssoapp.service.SsoConfigService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/admin/sso")
public class SsoConfigController {

    private static final Logger logger = LoggerFactory.getLogger(SsoConfigController.class);

    @Autowired
    private SsoConfigService ssoConfigService;

    @GetMapping("/config")
    @PreAuthorize("hasAnyAuthority('ROLE_TENANT_ADMIN', 'ROLE_SUPERADMIN')")
    public String ssoConfigPage(Model model) {
        logger.info("SSO Config page accessed");

        // Get current tenant ID
        String tenantIdString = TenantContext.getCurrentTenantId();
        logger.info("Current tenant context: {}", tenantIdString);

        // Get or initialize SSO configs for this tenant
        List<SsoConfig> ssoConfigs = ssoConfigService.getAllSsoConfigs();

        // If no configs exist, initialize them
        if (ssoConfigs.isEmpty() && tenantIdString != null && !tenantIdString.isEmpty()) {
            try {
                Long tenantId = Long.parseLong(tenantIdString);
                logger.info("No SSO configs found for tenant {}, initializing defaults", tenantId);
                ssoConfigService.initializeDefaultConfigsForTenant(tenantId);
                ssoConfigs = ssoConfigService.getAllSsoConfigs();
            } catch (NumberFormatException e) {
                logger.error("Invalid tenant ID format: {}", tenantIdString);
            }
        }

        logger.info("Loaded {} SSO configs", ssoConfigs.size());
        model.addAttribute("ssoConfigs", ssoConfigs);

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

            logger.info("Updating SSO config: {} to enabled={}", ssoType, enabled);
            SsoConfig updated = ssoConfigService.updateSsoConfig(ssoType.toUpperCase(), enabled);
            return ResponseEntity.ok(updated);
        } catch (Exception e) {
            logger.error("Failed to update SSO config: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to update SSO config: " + e.getMessage());
        }
    }

    @GetMapping("/config/{ssoType}/details")
    @PreAuthorize("hasAnyAuthority('ROLE_TENANT_ADMIN', 'ROLE_SUPERADMIN')")
    @ResponseBody
    public ResponseEntity<Map<String, String>> getSsoConfigDetails(@PathVariable String ssoType) {
        String type = ssoType.toUpperCase();
        logger.info("Fetching details for SSO type: {}", type);

        SsoConfig config = ssoConfigService.getSsoConfigByType(type);

        if (config == null) {
            logger.error("No config found for type: {}", type);
            return ResponseEntity.notFound().build();
        }

        Map<String, String> configMap = new HashMap<>();

        // Common properties
        configMap.put("ssoType", type);
        configMap.put("status", config.getEnabled() ? "Enabled" : "Disabled");
        configMap.put("provider", "MiniOrange");

        // Type-specific properties
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
                configMap.put("redirectUri", "http://localhost:8080/login/oauth2/code/miniorange");
                configMap.put("grantType", "authorization_code");
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
            logger.info("Updating SSO config details for: {}", ssoType);
            SsoConfig updatedConfig = ssoConfigService.updateSsoConfigDetails(ssoType.toUpperCase(), details);
            return ResponseEntity.ok(updatedConfig);
        } catch (Exception e) {
            logger.error("Failed to update config details for {}: {}", ssoType, e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to update configuration: " + e.getMessage());
        }
    }

    @GetMapping("/test/{ssoType}")
    @PreAuthorize("hasAnyAuthority('ROLE_TENANT_ADMIN', 'ROLE_SUPERADMIN')")
    public String testSso(@PathVariable String ssoType, jakarta.servlet.http.HttpServletRequest request) {
        String type = ssoType.toUpperCase();
        logger.info("Testing SSO type: {}", type);

        // Store admin session before test
        storeAdminSession(request);

        // Set test mode flag in session
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
    public String jwtTestCallback(@RequestParam("id_token") String jwt,
                                  jakarta.servlet.http.HttpServletRequest request,
                                  jakarta.servlet.http.HttpServletResponse response) throws java.io.IOException {
        Map<String, Object> testResult = new HashMap<>();
        Map<String, Object> attributes = new HashMap<>();
        String testStatus = "success";

        try {
            // Basic JWT decoding (without verification for test purposes)
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
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            request.getSession().setAttribute("admin_test_principal", auth);
            request.getSession().setAttribute("admin_test_authorities", auth.getAuthorities());
        }
    }

    private void restoreAdminSession(jakarta.servlet.http.HttpServletRequest request) {
        Authentication adminAuth =
                (Authentication) request.getSession().getAttribute("admin_test_principal");
        if (adminAuth != null) {
            org.springframework.security.core.context.SecurityContext securityContext =
                    SecurityContextHolder.getContext();
            securityContext.setAuthentication(adminAuth);

            HttpSession session = request.getSession();
            session.setAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                    securityContext
            );

            request.getSession().removeAttribute("admin_test_principal");
            request.getSession().removeAttribute("admin_test_authorities");
        }
    }
}