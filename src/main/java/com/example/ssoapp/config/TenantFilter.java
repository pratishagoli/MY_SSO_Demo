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
 * Servlet filter that resolves tenant from subdomain and sets TenantContext.
 * Runs BEFORE Spring Security filter chain.
 */
@Component
@Order(1) // Run before security filters
public class TenantFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(TenantFilter.class);

    @Autowired
    private TenantRepository tenantRepository;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String serverName = httpRequest.getServerName();

        logger.debug("Request to: {}", serverName);

        try {
            // Extract subdomain (e.g., "tenant1" from "tenant1.localhost")
            String subdomain = extractSubdomain(serverName);

            if (subdomain != null && !subdomain.isEmpty()) {
                // Tenant subdomain detected
                // Assuming Tenant model uses the subdomain itself as the primary ID/key for simplicity
                // but we check the database for validation and activation status.
                Optional<Tenant> tenant = tenantRepository.findBySubdomain(subdomain);

                if (tenant.isPresent() && tenant.get().getActive()) {
                    // 🚀 FIX: Convert Long ID (from DB) to String for TenantContext
                    String tenantIdString = String.valueOf(tenant.get().getId());

                    TenantContext.setTenantId(tenantIdString); // Set String ID
                    logger.info("Tenant context set: {} (ID: {})", subdomain, tenantIdString);
                } else {
                    logger.warn("Invalid or inactive tenant subdomain: {}", subdomain);
                    // Let request proceed; Spring Security will handle unauthorized access
                }
            } else {
                // No subdomain or "localhost" → SuperAdmin context
                TenantContext.clear();
                logger.debug("SuperAdmin context (no tenant)");
            }

            chain.doFilter(request, response);

        } finally {
            // Always clear after request
            TenantContext.clear();
        }
    }

    /**
     * Extract subdomain from hostname.
     * Examples:
     * - "tenant1.localhost" → "tenant1"
     * - "localhost" → null
     * - "tenant1.example.com" → "tenant1"
     */
    private String extractSubdomain(String serverName) {
        if (serverName == null || serverName.equals("localhost") || serverName.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            return null; // No subdomain
        }

        // Split by dot and take first part
        String[] parts = serverName.split("\\.");
        if (parts.length > 2) {
            return parts[0]; // e.g., "tenant1" from "tenant1.localhost"
        }

        return null;
    }
}