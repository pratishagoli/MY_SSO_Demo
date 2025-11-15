package com.example.ssoapp.config;

import com.example.ssoapp.model.Tenant;
import com.example.ssoapp.repository.TenantRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

/**
 * ✅ TenantFilter - Production-ready with configurable domain
 * Extracts tenant information (subdomain → tenant_id) per request
 * and sets it in TenantContext for multi-tenant isolation.
 */
@Component
@Order(1) // Ensures it runs before Spring Security filters
public class TenantFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(TenantFilter.class);

    @Autowired
    private TenantRepository tenantRepository;

    // ✅ Make the base domain configurable via application.properties
    @Value("${app.domain.base:localhost}")
    private String baseDomain;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String serverName = httpRequest.getServerName();
        String requestURI = httpRequest.getRequestURI();

        logger.debug("🌍 TenantFilter: host={}, uri={}", serverName, requestURI);

        try {
            // Extract subdomain (e.g., "my-sso-demo" from "my-sso-demo.pratisha.cfd")
            String subdomain = extractSubdomain(serverName);

            if (subdomain != null && !subdomain.isEmpty()) {
                logger.info("🔍 Tenant subdomain detected: '{}'", subdomain);

                // ✅ Lookup tenant in DB
                Optional<Tenant> tenantOpt = tenantRepository.findBySubdomain(subdomain);

                if (tenantOpt.isPresent()) {
                    Tenant tenant = tenantOpt.get();

                    // Check if tenant is active
                    if (!tenant.getActive()) {
                        logger.warn("⚠️ Tenant '{}' is INACTIVE", subdomain);
                        httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN,
                                "Tenant account is inactive");
                        return; // Stop filter chain
                    }

                    // Set tenant context
                    String tenantIdString = String.valueOf(tenant.getId());
                    TenantContext.setTenantId(tenantIdString);

                    logger.info("✅ Tenant context set: subdomain='{}', tenantId={}",
                            subdomain, tenantIdString);
                } else {
                    logger.error("❌ Unknown tenant subdomain: '{}' - Not found in database", subdomain);

                    // Send friendly error response
                    httpResponse.setStatus(HttpServletResponse.SC_NOT_FOUND);
                    httpResponse.setContentType("text/html");
                    httpResponse.getWriter().write(
                            "<html><body style='font-family: Arial, sans-serif; text-align: center; padding: 50px;'>" +
                                    "<h1>Tenant Not Found</h1>" +
                                    "<p>The subdomain '<strong>" + subdomain + "</strong>' does not exist.</p>" +
                                    "<p>Please check the URL and try again.</p>" +
                                    "<p><a href='https://" + baseDomain + "/login'>Go to main login</a></p>" +
                                    "</body></html>"
                    );
                    return; // Stop filter chain
                }
            } else {
                // ✅ No subdomain (e.g. pratisha.cfd) → SuperAdmin context
                TenantContext.clear();
                logger.debug("🧭 SuperAdmin context (no subdomain)");
            }

            // Proceed with request
            chain.doFilter(request, response);

        } catch (Exception e) {
            logger.error("💥 CRITICAL ERROR in TenantFilter for host '{}': {}",
                    serverName, e.getMessage(), e);

            // Send error response
            httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            httpResponse.setContentType("text/html");
            httpResponse.getWriter().write(
                    "<html><body style='font-family: Arial, sans-serif; text-align: center; padding: 50px;'>" +
                            "<h1>Tenant Filter Error</h1>" +
                            "<p>An error occurred while processing your request.</p>" +
                            "<p>Error: " + e.getMessage() + "</p>" +
                            "<p><a href='https://" + baseDomain + "/login'>Go to main login</a></p>" +
                            "</body></html>"
            );

        } finally {
            // ✅ Always clear TenantContext to prevent thread leakage
            TenantContext.clear();
        }
    }

    /**
     * Extract subdomain from hostname.
     *
     * Production Examples:
     * - my-sso-demo.pratisha.cfd → "my-sso-demo"
     * - pratisha.cfd → null (SuperAdmin)
     * - www.pratisha.cfd → null (ignore www prefix)
     *
     * Development Examples:
     * - pratik.localhost → "pratik"
     * - localhost → null
     */
    private String extractSubdomain(String serverName) {
        if (serverName == null) {
            return null;
        }

        // Remove port if present (e.g., "my-sso-demo.pratisha.cfd:8080" → "my-sso-demo.pratisha.cfd")
        if (serverName.contains(":")) {
            serverName = serverName.split(":")[0];
        }

        // Handle localhost or IP addresses (development mode)
        if (serverName.equalsIgnoreCase("localhost") ||
                serverName.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            return null; // No subdomain
        }

        // ✅ NEW: Check if this is the base domain (no subdomain)
        if (serverName.equalsIgnoreCase(baseDomain)) {
            return null; // This is the main domain - SuperAdmin access
        }

        // ✅ NEW: Check if this is www prefix - treat as base domain
        if (serverName.equalsIgnoreCase("www." + baseDomain)) {
            return null; // Redirect www to base domain
        }

        // ✅ PRODUCTION: Extract subdomain from multi-level domain
        // For "my-sso-demo.pratisha.cfd", extract "my-sso-demo"
        if (serverName.endsWith("." + baseDomain)) {
            String subdomain = serverName.substring(0, serverName.length() - baseDomain.length() - 1);

            // Validate subdomain format (alphanumeric and hyphens only)
            if (subdomain.matches("^[a-z0-9-]+$")) {
                return subdomain.toLowerCase();
            } else {
                logger.warn("Invalid subdomain format: {}", subdomain);
                return null;
            }
        }

        // ✅ DEVELOPMENT: Handle simple localhost subdomains
        // For "pratik.localhost", extract "pratik"
        String[] parts = serverName.split("\\.");
        if (parts.length >= 2) {
            String potential = parts[0];
            // Validate it's not "www" or other common prefixes
            if (!potential.equalsIgnoreCase("www") && potential.matches("^[a-z0-9-]+$")) {
                return potential.toLowerCase();
            }
        }

        return null;
    }
}