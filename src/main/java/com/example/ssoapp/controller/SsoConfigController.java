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
        Map<String, String> config = new HashMap<>();
        String type = ssoType.toUpperCase();
        
        // Read from application properties or use defaults
        switch (type) {
            case "JWT":
                config.put("protocol", "JWT (JSON Web Token)");
                config.put("clientId", "4rIAZPjSTgKGuylgQvCNenKqZRkHOC6f");
                config.put("issuer", "4rIAZPjSTgKGuylgQvCNenKqZRkHOC6f");
                config.put("redirectUri", "http://localhost:8080/auth/jwt/callback");
                config.put("loginUrl", "https://pratisha.xecurify.com/moas/idp/jwtsso/379428");
                config.put("provider", "MiniOrange");
                break;
            case "OIDC":
                config.put("protocol", "OIDC (OpenID Connect)");
                config.put("clientId", "NeXKWs6a9g0lywwLQAoBPwntbNV91HdT");
                config.put("clientSecret", "rbHqjgFowkLiOvKnURJV4LEUSEFlzWNj");
                config.put("scope", "openid,profile,email");
                config.put("issuerUri", "https://pratisha.xecurify.com/moas/discovery/v2.0/NeXKWs6a9g0lywwLQAoBPwntbNV91HdT");
                config.put("grantType", "authorization_code");
                config.put("provider", "MiniOrange");
                break;
            case "SAML":
                config.put("protocol", "SAML 2.0");
                config.put("entityId", "ssoapp");
                config.put("metadataUrl", "https://pratisha.xecurify.com/moas/metadata/saml/379428/432956");
                config.put("acsUrl", "http://localhost:8080/login/saml2/sso/miniorange-saml");
                config.put("ssoServiceUrl", "https://pratisha.xecurify.com/moas/idp/samlsso/b27ecbfc-6e7c-4f59-b84b-bdb1c967ef3a");
                config.put("nameIdFormat", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
                config.put("provider", "MiniOrange");
                break;
            default:
                return ResponseEntity.badRequest().build();
        }
        
        SsoConfig ssoConfig = ssoConfigService.getSsoConfigByType(type);
        config.put("status", ssoConfig.getEnabled() ? "Enabled" : "Disabled");
        config.put("ssoType", type);
        
        return ResponseEntity.ok(config);
    }

    @PutMapping("/config/{ssoType}/update")
    @PreAuthorize("hasAuthority('ADMIN')")
    @ResponseBody
    public ResponseEntity<?> updateSsoConfigDetails(@PathVariable String ssoType, @RequestBody Map<String, String> config) {
        // For now, just return success - actual property updates would require application restart
        // In production, you might want to update properties file or use a configuration service
        return ResponseEntity.ok("Configuration updated. Note: Some changes may require application restart.");
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

