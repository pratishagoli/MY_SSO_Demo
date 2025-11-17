package com.example.ssoapp.repository;

import com.example.ssoapp.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // ✅ SUPERADMIN LOGIN - Find by email where role is SUPERADMIN
    @Query("SELECT u FROM User u WHERE LOWER(u.email) = LOWER(:email) AND u.role = com.example.ssoapp.model.Role.SUPERADMIN")
    Optional<User> findSuperAdminByEmail(@Param("email") String email);

    // ✅ TENANT-BASED LOGIN - Find by username or email within a specific tenant
    @Query("SELECT u FROM User u WHERE (LOWER(u.username) = LOWER(:usernameOrEmail) OR LOWER(u.email) = LOWER(:usernameOrEmail)) AND u.tenantId = :tenantId")
    Optional<User> findByUsernameOrEmailAndTenantId(
            @Param("usernameOrEmail") String usernameOrEmail,
            @Param("tenantId") String tenantId);

    // ✅ FIND USER BY EMAIL (for admin operations)
    Optional<User> findByEmail(String email);

    // ✅ CHECKS for registration/validation
    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByEmailIgnoreCase(String email);
}