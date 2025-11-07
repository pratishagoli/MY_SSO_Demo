package com.example.ssoapp.config;

import com.example.ssoapp.model.Tenant;
import com.example.ssoapp.repository.TenantRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

/**
 * ✅ TenantFilter
 * Extracts tenant information (subdomain → tenant_id) per request
 * and sets it in TenantContext for multi-tenant isolation.
 * Clears context after each request automatically.
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
        String serverName = httpRequest.getServerName();

        logger.debug("🌍 Incoming request from host: {}", serverName);

        try {
            // Extract subdomain (e.g., "tenant1" from "tenant1.localhost")
            String subdomain = extractSubdomain(serverName);

            if (subdomain != null && !subdomain.isEmpty()) {
                // ✅ Tenant subdomain detected → lookup in DB
                Optional<Tenant> tenant = tenantRepository.findBySubdomain(subdomain);

                if (tenant.isPresent()) {
                    Tenant currentTenant = tenant.get();
                    String tenantIdString = String.valueOf(currentTenant.getId()); // ✅ Convert Long → String
                    TenantContext.setTenantId(tenantIdString);

                    logger.info("🏢 Tenant context set: subdomain='{}', tenantId={}", subdomain, tenantIdString);
                } else {
                    logger.warn("⚠️ Unknown tenant subdomain: '{}'", subdomain);
                    // Still continue — user will hit unauthorized later
                }
            } else {
                // ✅ No subdomain (e.g. localhost:8080) → SuperAdmin context
                TenantContext.clear();
                logger.debug("🧭 SuperAdmin context detected (no subdomain)");
            }

            // Proceed with request
            chain.doFilter(request, response);

        } finally {
            // ✅ Always clear TenantContext to prevent thread leakage
            TenantContext.clear();
        }
    }

    /**
     * Utility method to extract subdomain from host name.
     * Examples:
     * - tenant1.localhost → tenant1
     * - localhost → null
     * - tenant1.example.com → tenant1
     */
    private String extractSubdomain(String serverName) {
        if (serverName == null ||
                serverName.equalsIgnoreCase("localhost") ||
                serverName.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            return null; // No subdomain for localhost or IP
        }

        String[] parts = serverName.split("\\.");
        if (parts.length >= 2) {
            return parts[0]; // Take first part as subdomain
        }
        return null;
    }
}