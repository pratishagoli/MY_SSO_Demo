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
 * ✅ TenantFilter - Enhanced with production domain support
 * Extracts tenant information (subdomain → tenant_id) per request
 * and sets it in TenantContext for multi-tenant isolation.
 */
@Component
@Order(1)
public class TenantFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(TenantFilter.class);

    @Autowired
    private TenantRepository tenantRepository;

    // Base domain configuration - can be set in application.properties
    @Value("${app.base-domain:localhost}")
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
            // Extract subdomain
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
                        sendErrorPage(httpResponse,
                                "Tenant Inactive",
                                "This tenant account is currently inactive. Please contact support.",
                                HttpServletResponse.SC_FORBIDDEN);
                        return;
                    }

                    // Set tenant context
                    String tenantIdString = String.valueOf(tenant.getId());
                    TenantContext.setTenantId(tenantIdString);

                    logger.info("✅ Tenant context set: subdomain='{}', tenantId={}",
                            subdomain, tenantIdString);
                } else {
                    logger.error("❌ Unknown tenant subdomain: '{}' - Not found in database", subdomain);
                    sendErrorPage(httpResponse,
                            "Tenant Not Found",
                            "The subdomain '<strong>" + subdomain + "</strong>' does not exist.",
                            HttpServletResponse.SC_NOT_FOUND);
                    return;
                }
            } else {
                // ✅ No subdomain → SuperAdmin context
                TenantContext.clear();
                logger.debug("🧭 SuperAdmin context (no subdomain)");
            }

            // Proceed with request
            chain.doFilter(request, response);

        } catch (Exception e) {
            logger.error("💥 CRITICAL ERROR in TenantFilter for host '{}': {}",
                    serverName, e.getMessage(), e);
            sendErrorPage(httpResponse,
                    "Server Error",
                    "An error occurred while processing your request: " + e.getMessage(),
                    HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

        } finally {
            // ✅ Always clear TenantContext
            TenantContext.clear();
        }
    }

    /**
     * Extract subdomain from hostname with support for production domains
     * Examples:
     * - pratisha.cfd → null (base domain, SuperAdmin)
     * - localhost → null (local dev, SuperAdmin)
     * - tenant1.pratisha.cfd → "tenant1"
     * - tenant1.localhost → "tenant1"
     * - 192.168.1.1 → null (IP address, SuperAdmin)
     */
    private String extractSubdomain(String serverName) {
        if (serverName == null || serverName.isEmpty()) {
            return null;
        }

        // Remove port if present
        if (serverName.contains(":")) {
            serverName = serverName.split(":")[0];
        }

        serverName = serverName.toLowerCase().trim();

        // Handle IP addresses
        if (serverName.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            return null;
        }

        // Check if this is the base domain (no subdomain)
        if (serverName.equals(baseDomain)) {
            return null; // SuperAdmin context
        }

        // Check if this matches base domain pattern (e.g., "pratisha.cfd")
        if (baseDomain.contains(".")) {
            String[] baseParts = baseDomain.split("\\.");
            String[] serverParts = serverName.split("\\.");

            // If same number of parts, it's the base domain
            if (serverParts.length == baseParts.length) {
                return null;
            }

            // Extract subdomain (everything before the base domain)
            if (serverName.endsWith("." + baseDomain)) {
                String subdomain = serverName.substring(0, serverName.length() - baseDomain.length() - 1);
                // Validate subdomain format
                if (subdomain.matches("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")) {
                    return subdomain;
                }
            }
        } else {
            // Simple domain like "localhost"
            String[] parts = serverName.split("\\.");
            if (parts.length >= 2 && !parts[0].equalsIgnoreCase("www")) {
                return parts[0];
            }
        }

        return null;
    }

    /**
     * Send a styled error page to the user
     */
    private void sendErrorPage(HttpServletResponse response, String title, String message, int statusCode)
            throws IOException {
        response.setStatus(statusCode);
        response.setContentType("text/html; charset=UTF-8");
        response.getWriter().write(
                "<!DOCTYPE html>" +
                        "<html>" +
                        "<head>" +
                        "<title>" + title + "</title>" +
                        "<style>" +
                        "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; " +
                        "       background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); " +
                        "       display: flex; align-items: center; justify-content: center; " +
                        "       min-height: 100vh; margin: 0; }" +
                        ".container { background: white; padding: 40px; border-radius: 12px; " +
                        "             box-shadow: 0 10px 40px rgba(0,0,0,0.2); max-width: 500px; text-align: center; }" +
                        "h1 { color: #333; margin-bottom: 20px; }" +
                        "p { color: #666; line-height: 1.6; margin-bottom: 30px; }" +
                        "a { display: inline-block; background: #667eea; color: white; " +
                        "    padding: 12px 30px; text-decoration: none; border-radius: 6px; " +
                        "    transition: background 0.3s; }" +
                        "a:hover { background: #5568d3; }" +
                        "</style>" +
                        "</head>" +
                        "<body>" +
                        "<div class='container'>" +
                        "<h1>" + title + "</h1>" +
                        "<p>" + message + "</p>" +
                        "<a href='https://" + baseDomain + "/login'>Go to Main Login</a>" +
                        "</div>" +
                        "</body>" +
                        "</html>"
        );
    }
}