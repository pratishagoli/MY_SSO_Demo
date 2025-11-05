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
    public ResponseEntity<Map<String, String>> getSsoConfigDetails(@PathVariable String ssoType) {
        String type = ssoType.toUpperCase();
        SsoConfig config = ssoConfigService.getSsoConfigByType(type);
        Map<String, String> configMap = new HashMap<>();

        // Common properties
        configMap.put("ssoType", type);
        configMap.put("status", config.getEnabled() ? "Enabled" : "Disabled");
        configMap.put("provider", "MiniOrange");

        // Read properties from database
        switch (type) {
            case "JWT":
                configMap.put("protocol", "JWT (JSON Web Token)");
                // These are hardcoded in your app.properties
                configMap.put("clientId", "4rIAZPjSTgKGuylgQvCNenKqZRkHOC6f");
                configMap.put("issuer", "4rIAZPjSTgKGuylgQvCNenKqZRkHOC6f");
                configMap.put("redirectUri", "http://localhost:8080/auth/jwt/callback");
                configMap.put("loginUrl", "https://pratisha.xecurify.com/moas/idp/jwtsso/379428");
                break;
            case "OIDC":
                configMap.put("protocol", "OIDC (OpenID Connect)");
                // These are hardcoded in your app.properties
                configMap.put("clientId", "NeXKWs6a9g0lywwLQAoBPwntbNV91HdT");
                configMap.put("clientSecret", "rbHqjgFowkLiOvKnURJV4LEUSEFlzWNj");
                configMap.put("scope", "openid,profile,email");
                configMap.put("issuerUri", "https://pratisha.xecurify.com/moas/discovery/v2.0/NeXKWs6a9g0lywwLQAoBPwntbNV91HdT");
                configMap.put("grantType", "authorization_code");
                break;
            case "SAML":
                configMap.put("protocol", "SAML 2.0");
                // These now come from the DATABASE
                configMap.put("entityId", config.getSpEntityId());
                configMap.put("metadataUrl", config.getConfigUrl()); // The metadata URL from miniOrange
                configMap.put("ssoServiceUrl", config.getIdpSsoUrl()); // The "SAML Login URL"
                configMap.put("idpEntityId", config.getIdpEntityId()); // The "IDP Entity ID or Issuer"
                configMap.put("idpCertificateContent", config.getIdpCertificateContent()); // The "X.509 Certificate"

                // This is static for your app
                configMap.put("acsUrl", "http://localhost:8080/login/saml2/sso/miniorange-saml");
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
            // This is the method that needs to exist in your SsoConfigService
            // It will find the config and update its fields
            SsoConfig updatedConfig = ssoConfigService.updateSsoConfigDetails(ssoType.toUpperCase(), details);
            return ResponseEntity.ok(updatedConfig);
        } catch (Exception e) {
            logger.error("Failed to update config details for {}: {}", ssoType, e.getMessage(), e);
            return ResponseEntity.badRequest().body("Failed to update configuration: " + e.getMessage());
        }
    }

    @GetMapping("/test/{ssoType}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public String testSso(@PathVariable String ssoType, jakarta.servlet.http.HttpServletRequest request) {
        String type = ssoType.toUpperCase();
        
        // Store admin session before test
        storeAdminSession(request);
        
        // Set test mode flag in session
        request.getSession().setAttribute("sso_test_mode", true);
        request.getSession().setAttribute("sso_test_type", type);
        
        switch (type) {
            case "JWT":
                // Use the correct callback URL that's registered with miniOrange
                // Store test flag to redirect after callback
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
            // Basic JWT decoding (without verification for test purposes)
            String[] parts = jwt.split("\\.");
            if (parts.length >= 2) {
                // Decode payload (base64)
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
        
        // Store in session for modal popup
        request.getSession().setAttribute("sso_test_result", testResult);
        
        // Restore admin session and redirect back to config page
        restoreAdminSession(request);
        
        response.sendRedirect("/admin/sso/config?test=success");
        return null;
    }

    @GetMapping("/test/result")
    @ResponseBody
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Map<String, Object>> getTestResult(jakarta.servlet.http.HttpServletRequest request) {
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) request.getSession().getAttribute("sso_test_result");
        if (result != null) {
            // Store SAML assertion in DB if available
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
        // Store admin authentication info in session before test
        org.springframework.security.core.Authentication auth = 
            org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            request.getSession().setAttribute("admin_test_principal", auth);
            request.getSession().setAttribute("admin_test_authorities", auth.getAuthorities());
        }
    }

    private void restoreAdminSession(jakarta.servlet.http.HttpServletRequest request) {
        // Restore admin authentication after test
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

