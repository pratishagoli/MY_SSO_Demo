package com.example.ssoapp.config;

/**
 * ThreadLocal storage for current tenant ID (String/Subdomain).
 * Accessed throughout the request lifecycle to filter data by tenant.
 */
public class TenantContext {

    // 🚀 FIX 1: Change ThreadLocal type from Long to String
    private static final ThreadLocal<String> CURRENT_TENANT = new ThreadLocal<>();

    // 🚀 FIX 2: Change parameter type from Long to String
    public static void setTenantId(String tenantId) {
        CURRENT_TENANT.set(tenantId);
    }

    // 🚀 FIX 3: Rename method and change return type to String
    // This resolves both the method name and the return type mismatch in UserDetailsServiceImpl
    public static String getCurrentTenantId() {
        return CURRENT_TENANT.get();
    }

    public static void clear() {
        CURRENT_TENANT.remove();
    }
}
// Note: isSuperAdmin() logic is implicitly handled if getCurrentTenantId() returns null or an empty string.