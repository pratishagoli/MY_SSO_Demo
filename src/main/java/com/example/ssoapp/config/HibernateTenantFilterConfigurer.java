package com.example.ssoapp.config;

import com.example.ssoapp.model.Role;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
// import org.springframework.stereotype.Component; // ← COMMENT THIS OUT
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * TEMPORARILY DISABLED
 * Ensures the Hibernate filter is applied to the EntityManager (Session)
 * after the TenantContext has been set by TenantFilter.
 */
// @Component // ← COMMENTED OUT TO DEBUG
public class HibernateTenantFilterConfigurer extends OncePerRequestFilter {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String tenantId = TenantContext.getCurrentTenantId();

        if (tenantId != null && !tenantId.isEmpty()) {
            Session session = entityManager.unwrap(Session.class);
            session.enableFilter("tenantFilter")
                    .setParameter("tenantId", Long.valueOf(tenantId));
        }

        filterChain.doFilter(request, response);
    }
}