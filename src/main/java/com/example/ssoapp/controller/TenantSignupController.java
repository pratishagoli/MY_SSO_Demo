package com.example.ssoapp.controller;

import com.example.ssoapp.dto.CreateTenantRequest;
import com.example.ssoapp.service.TenantService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Public controller for tenant self-service signup
 * Accessible without authentication
 */
@Controller
public class TenantSignupController {

    private static final Logger logger = LoggerFactory.getLogger(TenantSignupController.class);

    @Autowired
    private TenantService tenantService;

    /**
     * Display the tenant signup page
     */
    @GetMapping("/tenant-signup")
    public String showTenantSignupPage() {
        logger.info("Tenant signup page accessed");
        return "tenant_signup";
    }

    /**
     * Handle tenant registration via API
     */
    @PostMapping("/api/tenant/signup")
    @ResponseBody
    public ResponseEntity<?> registerTenant(@RequestBody CreateTenantRequest request) {
        logger.info("Tenant registration attempt - Subdomain: {}, Email: {}",
                request.getSubdomain(), request.getAdminEmail());

        try {
            // Validate input
            if (request.getOrgName() == null || request.getOrgName().trim().isEmpty()) {
                return ResponseEntity.badRequest().body("Organization name is required");
            }

            if (request.getSubdomain() == null || request.getSubdomain().trim().isEmpty()) {
                return ResponseEntity.badRequest().body("Subdomain is required");
            }

            if (request.getAdminEmail() == null || request.getAdminEmail().trim().isEmpty()) {
                return ResponseEntity.badRequest().body("Admin email is required");
            }

            if (request.getAdminPassword() == null || request.getAdminPassword().length() < 6) {
                return ResponseEntity.badRequest().body("Password must be at least 6 characters");
            }

            // Validate subdomain format
            if (!request.getSubdomain().matches("^[a-z0-9-]+$")) {
                return ResponseEntity.badRequest()
                        .body("Subdomain can only contain lowercase letters, numbers, and hyphens");
            }

            // Create the tenant
            tenantService.createTenant(
                    request.getOrgName(),
                    request.getAdminEmail(),
                    request.getAdminPassword(),
                    request.getSubdomain()
            );

            logger.info("Tenant created successfully - Subdomain: {}", request.getSubdomain());

            return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                    "message", "Tenant created successfully",
                    "subdomain", request.getSubdomain(),
                    "loginUrl", "http://" + request.getSubdomain() + ".pratisha.cfd/login"
            ));

        } catch (RuntimeException e) {
            logger.error("Tenant registration failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error during tenant registration", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An unexpected error occurred. Please try again.");
        }
    }
}