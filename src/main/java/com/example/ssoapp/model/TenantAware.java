package com.example.ssoapp.model;

/**
 * Marker interface for entities that belong to a tenant.
 * All tenant-scoped entities should implement this.
 */
public interface TenantAware {
    Long getTenantId();
    void setTenantId(Long tenantId);
}