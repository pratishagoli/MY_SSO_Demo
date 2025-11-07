package com.example.ssoapp.config;

/**
 * TenantContext manages the current tenant identifier
 * throughout the lifecycle of a request.
 *
 * ✅ Thread-safe via ThreadLocal
 * ✅ Works for both tenant and superadmin contexts
 * ✅ Compatible with String-based tenant IDs
 */
public class TenantContext {

    // ============================================================
    //                  THREADLOCAL STORAGE
    // ============================================================
    private static final ThreadLocal<String> CURRENT_TENANT = new ThreadLocal<>();

    // ============================================================
    //                  SETTERS
    // ============================================================

    /**
     * Sets the current tenant ID for the active request/thread.
     *
     * @param tenantId the tenant ID or subdomain name
     */
    public static void setTenantId(String tenantId) {
        CURRENT_TENANT.set(tenantId);
    }

    // ============================================================
    //                  GETTERS
    // ============================================================

    /**
     * Retrieves the current tenant ID (String form).
     * Returns null if in superadmin context or not set.
     *
     * @return current tenant ID (String) or null
     */
    public static String getCurrentTenantId() {
        return CURRENT_TENANT.get();
    }

    /**
     * Retrieves the tenant ID as a Long (if numeric).
     * Useful for JPA entities using numeric tenant IDs.
     *
     * @return tenant ID as Long or null
     */
    public static Long getTenantIdAsLong() {
        try {
            String value = CURRENT_TENANT.get();
            return (value != null && !value.isBlank()) ? Long.valueOf(value) : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    // ============================================================
    //                  CONTEXT MANAGEMENT
    // ============================================================

    /**
     * Clears the tenant context after a request completes.
     * This prevents memory leaks between threads.
     */
    public static void clear() {
        CURRENT_TENANT.remove();
    }

    // ============================================================
    //                  CONTEXT HELPERS
    // ============================================================

    /**
     * Determines whether the current request
     * is operating in the SuperAdmin context.
     *
     * @return true if tenantId is null or empty
     */
    public static boolean isSuperAdminContext() {
        String tenantId = CURRENT_TENANT.get();
        return (tenantId == null || tenantId.isBlank());
    }

    /**
     * Returns a readable description of the current tenant context.
     *
     * @return debug info string
     */
    public static String describe() {
        String tenantId = CURRENT_TENANT.get();
        if (tenantId == null || tenantId.isBlank()) {
            return "SuperAdmin (no tenant)";
        }
        return "TenantContext active for ID: " + tenantId;
    }
}