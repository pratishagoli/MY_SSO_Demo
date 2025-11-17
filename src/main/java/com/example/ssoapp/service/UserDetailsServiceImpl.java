package com.example.ssoapp.service;

import com.example.ssoapp.model.User;
import com.example.ssoapp.repository.UserRepository;
import com.example.ssoapp.config.TenantContext;
import com.example.ssoapp.model.Role;
import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.Query;
import org.hibernate.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Collection;
import java.util.Optional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    private final UserRepository userRepository;
    private final EntityManager entityManager;

    public UserDetailsServiceImpl(UserRepository userRepository, EntityManager entityManager) {
        this.userRepository = userRepository;
        this.entityManager = entityManager;
    }

    /**
     * CRITICAL FIX: Native SQL query to bypass Hibernate filters completely
     */
    private Optional<User> findSuperAdminByEmailNative(String email) {
        try {
            logger.info("🔍 Attempting NATIVE SQL lookup for SuperAdmin: {}", email);
            
            // Use native SQL to completely bypass Hibernate filters
            String sql = "SELECT * FROM users WHERE LOWER(email) = LOWER(:email) AND role = 'SUPERADMIN' AND tenant_id IS NULL";
            
            Query query = entityManager.createNativeQuery(sql, User.class);
            query.setParameter("email", email);
            
            User superAdmin = (User) query.getSingleResult();
            logger.info("✅ SuperAdmin found via NATIVE SQL! Email: {}, Role: {}", 
                superAdmin.getEmail(), superAdmin.getRole());
            return Optional.of(superAdmin);
            
        } catch (NoResultException e) {
            logger.error("❌ SuperAdmin NOT FOUND via NATIVE SQL for email: {}", email);
            logger.error("💡 Run this query manually: SELECT * FROM users WHERE email='{}' AND role='SUPERADMIN' AND tenant_id IS NULL;", email);
            return Optional.empty();
        } catch (Exception e) {
            logger.error("💥 Error during SuperAdmin NATIVE SQL lookup: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String input) throws UsernameNotFoundException {

        logger.info("========================================");
        logger.info("🔐 LOGIN ATTEMPT");
        logger.info("========================================");
        logger.info("Input (email/username): {}", input);

        User user = null;
        String currentTenantId = TenantContext.getCurrentTenantId();

        logger.info("Current TenantContext ID: {}", currentTenantId != null ? currentTenantId : "NULL (SuperAdmin context)");

        // 🧩 1️⃣ SuperAdmin login (no tenant) - FIXED WITH NATIVE SQL
        if (currentTenantId == null || currentTenantId.isEmpty()) {
            logger.info("🔍 Attempting SuperAdmin login via NATIVE SQL...");
            
            Optional<User> superAdminOpt = findSuperAdminByEmailNative(input);

            if (superAdminOpt.isPresent()) {
                user = superAdminOpt.get();
                logger.info("✅ SuperAdmin found! Email: {}, Role: {}", user.getEmail(), user.getRole());
            } else {
                logger.error("❌ SuperAdmin NOT FOUND for email: {}", input);
                logger.error("💡 TROUBLESHOOTING:");
                logger.error("   1. Connect to your database and run:");
                logger.error("      SELECT id, email, username, role, tenant_id, password FROM users WHERE email = '{}';", input);
                logger.error("   2. Verify the SuperAdmin record exists with:");
                logger.error("      - email = '{}'", input);
                logger.error("      - role = 'SUPERADMIN' (not 'ROLE_SUPERADMIN')");
                logger.error("      - tenant_id = NULL");
                logger.error("      - password starts with $2a$ (BCrypt hash)");
                logger.error("   3. If record doesn't exist, create it manually:");
                logger.error("      INSERT INTO users (email, username, password, role, tenant_id, provider, created_at, updated_at)");
                logger.error("      VALUES ('{}', 'superadmin', '$2a$10$...YourBCryptHashHere...', 'SUPERADMIN', NULL, 'LOCAL', NOW(), NOW());", input);
            }
        }

        // 🧩 2️⃣ Tenant-specific login
        if (user == null && currentTenantId != null && !currentTenantId.isEmpty()) {
            logger.info("🔍 Attempting tenant-specific login for tenant: {}", currentTenantId);

            Optional<User> tenantUserOpt = userRepository.findByUsernameOrEmailAndTenantId(input, currentTenantId);

            if (tenantUserOpt.isPresent()) {
                user = tenantUserOpt.get();
                logger.info("✅ Tenant user found! Email: {}, Role: {}, TenantId: {}",
                            user.getEmail(), user.getRole(), user.getTenantId());
            } else {
                logger.error("❌ User NOT FOUND in tenant '{}' for input: {}", currentTenantId, input);
                throw new UsernameNotFoundException("User not found in tenant '" + currentTenantId + "': " + input);
            }
        }
        
        // 🧩 3️⃣ Final validation
        if (user == null) {
            logger.error("❌ AUTHENTICATION FAILED: User not found for input: {}", input);
            throw new UsernameNotFoundException("User not found: " + input);
        }

        // 🧩 4️⃣ Verify password is set
        if (user.getPassword() == null || user.getPassword().isEmpty()) {
            logger.error("❌ User {} has NO PASSWORD set in database!", user.getEmail());
            throw new UsernameNotFoundException("User account is not properly configured");
        }

        logger.info("✅ User loaded successfully: {}", user.getEmail());
        logger.info("   - Role: {}", user.getRole());
        logger.info("   - TenantId: {}", user.getTenantId());
        logger.info("   - Password hash starts with: {}", user.getPassword().substring(0, Math.min(10, user.getPassword().length())));

        // 🧩 5️⃣ Build user authorities from Role Enum
        Collection<? extends GrantedAuthority> authorities =
                Collections.singletonList(new SimpleGrantedAuthority(user.getRole().withPrefix()));

        logger.info("   - Granted Authority: {}", authorities);
        logger.info("========================================");

        // 🧩 6️⃣ Return Spring Security User object
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(), 
                user.getPassword(),
                authorities
        );
    }
}