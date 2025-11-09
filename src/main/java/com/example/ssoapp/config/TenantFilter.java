package com.example.ssoapp.config;

import com.example.ssoapp.model.Tenant;
import com.example.ssoapp.repository.TenantRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

/**
 * ✅ TenantFilter - Enhanced with better error handling
 * Extracts tenant information (subdomain → tenant_id) per request
 * and sets it in TenantContext for multi-tenant isolation.
 */
@Component
@Order(1) // Ensures it runs before Spring Security filters
public class TenantFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(TenantFilter.class);

    @Autowired
    private TenantRepository tenantRepository;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String serverName = httpRequest.getServerName();
        String requestURI = httpRequest.getRequestURI();

        logger.debug("🌍 TenantFilter: host={}, uri={}", serverName, requestURI);
        // Skip filtering for admin SSO routes when no subdomain
        if (requestURI.startsWith("/admin/sso") &&
                (serverName.equals("localhost") || !serverName.contains("."))) {
            logger.info("⚠️ Skipping tenant filter for SSO config access");
            chain.doFilter(request, response);
            return;
        }

        // ✅ NEW: Skip tenant filtering for SuperAdmin SSO config routes
        if (requestURI.startsWith("/superadmin") ||
                (requestURI.startsWith("/admin/sso") && (serverName.equals("localhost") || serverName.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")))) {
            logger.debug("🧭 Skipping tenant filter for SuperAdmin route: {}", requestURI);
            chain.doFilter(request, response);
            return;
        }
        try {
            // Extract subdomain (e.g., "pratik" from "pratik.localhost")
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
                            "<html><body>" +
                                    "<h1>Tenant Not Found</h1>" +
                                    "<p>The subdomain '<strong>" + subdomain + "</strong>' does not exist.</p>" +
                                    "<p>Please check the URL and try again.</p>" +
                                    "<p><a href='http://localhost:8080/login'>Go to main login</a></p>" +
                                    "</body></html>"
                    );
                    return; // Stop filter chain
                }
            } else {
                // ✅ No subdomain (e.g. localhost:8080) → SuperAdmin context
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
                    "<html><body>" +
                            "<h1>Tenant Filter Error</h1>" +
                            "<p>An error occurred while processing your request.</p>" +
                            "<p>Error: " + e.getMessage() + "</p>" +
                            "<p><a href='http://localhost:8080/login'>Go to main login</a></p>" +
                            "</body></html>"
            );

        } finally {
            // ✅ Always clear TenantContext to prevent thread leakage
            TenantContext.clear();
        }
    }

    /**
     * Extract subdomain from hostname.
     * Examples:
     * - pratik.localhost → "pratik"
     * - localhost → null
     * - pratik.example.com → "pratik"
     */
    private String extractSubdomain(String serverName) {
        if (serverName == null) {
            return null;
        }

        // Remove port if present (e.g., "pratik.localhost:8080" → "pratik.localhost")
        if (serverName.contains(":")) {
            serverName = serverName.split(":")[0];
        }

        // Handle localhost or IP addresses
        if (serverName.equalsIgnoreCase("localhost") ||
                serverName.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            return null; // No subdomain
        }

        // Split by dot and take first part
        String[] parts = serverName.split("\\.");
        if (parts.length >= 2) {
            String potential = parts[0];
            // Validate it's not "www" or other common prefixes
            if (!potential.equalsIgnoreCase("www")) {
                return potential.toLowerCase();
            }
        }

        return null;
    }
}