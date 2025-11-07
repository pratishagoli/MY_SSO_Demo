package com.example.ssoapp.config;

import com.example.ssoapp.model.Role;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Ensures the Hibernate filter is applied to the EntityManager (Session)
 * after the TenantContext has been set by TenantFilter.
 */
@Component
public class HibernateTenantFilterConfigurer extends OncePerRequestFilter {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // The TenantContext is already set by the TenantFilter which runs before this.

        try {
            String tenantId = TenantContext.getCurrentTenantId();

            if (tenantId != null && !tenantId.isEmpty()) {
                // If a tenant is present, enable the filter
                Session session = entityManager.unwrap(Session.class);
                session.enableFilter("tenantFilter")
                        .setParameter("tenantId", tenantId)
                        .validate(); // 🚀 FIX: Removed the 'true' argument

                // logger.info("Hibernate Filter Enabled for Tenant: {}", tenantId);
            } else {
                // If tenantId is null (Superadmin or main domain), the filter remains disabled.
                // logger.info("Hibernate Filter Disabled (Superadmin/Global Context)");
            }

            filterChain.doFilter(request, response);

        } finally {
            // Cleanup logic reminder
        }
    }
}