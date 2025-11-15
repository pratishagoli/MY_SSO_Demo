package com.example.ssoapp.controller;

import com.example.ssoapp.model.SsoConfig;
import com.example.ssoapp.service.SsoConfigService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;

import java.util.HashMap;
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

    // ✅ Inject base URL from config
    @Value("${app.domain.url}")
    private String baseUrl;

    @GetMapping("/config")
    @PreAuthorize("hasAuthority('ADMIN')")
    public String ssoConfigPage(Model model) {
        model.addAttribute("ssoConfigs", ssoConfigService.getAllSsoConfigs());
        return "ssoconfig";
    }

    @PutMapping("/config/{ssoType}")
    @PreAuthorize("hasAuthority('ADMIN')")
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
            return ResponseEntity.badRequest().body("Failed to update SSO config: " + e.getMessage());
        }
    }

    @GetMapping("/config/{ssoType}/details")
    @PreAuthorize("hasAuthority('ADMIN')")
    @ResponseBody
    public ResponseEntity<Map<String, String>> getSsoConfigDetails(@PathVariable String ssoType, HttpServletRequest request) {
        String type = ssoType.toUpperCase();
        SsoConfig config = ssoConfigService.getSsoConfigByType(type);
        Map<String, String> configMap = new HashMap<>();

        // ✅ Determine the current subdomain/domain
        String currentHost = request.getServerName();
        String currentUrl = request.getScheme() + "://" + currentHost;

        // Common properties
        configMap.put("ssoType", type);
        configMap.put("status", config.getEnabled() ? "Enabled" : "Disabled");
        configMap.put("provider", "MiniOrange");

        // Read properties from database
        switch (type) {
            case "JWT":
                configMap.put("protocol", "JWT (JSON Web Token)");
                configMap.put("clientId", config.getClientId());
                configMap.put("issuerUri", config.getIssuerUri());
                // ✅ Use current host for redirect URI
                configMap.put("redirectUri", currentUrl + "/auth/jwt/callback");
                configMap.put("loginUrl", config.getConfigUrl());
                break;

            case "OIDC":
                configMap.put("protocol", "OIDC (OpenID Connect)");
                configMap.put("clientId", config.getClientId());
                configMap.put("clientSecret", config.getClientSecret());
                configMap.put("scope", "openid,profile,email");
                configMap.put("issuerUri", config.getIssuerUri());
                // ✅ Use current host for redirect URI
                configMap.put("redirectUri", currentUrl + "/login/oauth2/code/miniorange");
                configMap.put("grantType", "authorization_code");
                break;

            case "SAML":
                configMap.put("protocol", "SAML 2.0");
                configMap.put("entityId", config.getSpEntityId());
                configMap.put("metadataUrl", config.getConfigUrl());
                configMap.put("ssoServiceUrl", config.getIdpSsoUrl());
                configMap.put("idpEntityId", config.getIdpEntityId());
                configMap.put("idpCertificateContent", config.getIdpCertificateContent());
                // ✅ Use current host for ACS URL
                configMap.put("acsUrl", currentUrl + "/login/saml2/sso/miniorange-saml");
                configMap.put("nameIdFormat", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
                break;

            default:
                return ResponseEntity.badRequest().build();
        }

        return ResponseEntity.ok(configMap);
    }

    @PutMapping("/config/{ssoType}/update")
    @PreAuthorize("hasAuthority('ADMIN')")
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

    @GetMapping("/test/{ssoType}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public String testSso(@PathVariable String ssoType, HttpServletRequest request) {
        String type = ssoType.toUpperCase();

        // Store admin session before test
        storeAdminSession(request);

        // Set test mode flag in session
        request.getSession().setAttribute("sso_test_mode", true);
        request.getSession().setAttribute("sso_test_type", type);

        // ✅ Use dynamic URLs based on current host
        String currentUrl = request.getScheme() + "://" + request.getServerName();

        switch (type) {
            case "JWT":
                return "redirect:https://pratisha.xecurify.com/moas/idp/jwtsso/379428?client_id=4rIAZPjSTgKGuylgQvCNenKqZRkHOC6f&redirect_uri=" + currentUrl + "/auth/jwt/callback";
            case "OIDC":
                return "redirect:/oauth2/authorization/miniorange";
            case "SAML":
                return "redirect:/saml2/authenticate/miniorange-saml";
            default:
                return "redirect:/admin/sso/config?error=invalid_sso_type";
        }
    }

    @GetMapping("/test/jwt/callback")
    public String jwtTestCallback(@RequestParam("id_token") String jwt, HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response) throws java.io.IOException {
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
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Map<String, Object>> getTestResult(HttpServletRequest request) {
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

    private void storeAdminSession(HttpServletRequest request) {
        org.springframework.security.core.Authentication auth =
                org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            request.getSession().setAttribute("admin_test_principal", auth);
            request.getSession().setAttribute("admin_test_authorities", auth.getAuthorities());
        }
    }

    private void restoreAdminSession(HttpServletRequest request) {
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