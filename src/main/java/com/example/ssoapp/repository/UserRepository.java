package com.example.ssoapp.repository;

import com.example.ssoapp.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param; // <-- Make sure this import is added
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // ✅ SUPERADMIN LOGIN
    // (Added @Param for clarity and robustness)
    @Query("SELECT u FROM User u WHERE LOWER(u.email) = LOWER(:email) AND u.role = com.example.ssoapp.model.Role.SUPERADMIN")
    Optional<User> findSuperAdminByEmail(@Param("email") String email);

    // ✅ TENANT-BASED LOGIN
    // (FIXED: Method signature now has 2 arguments matching the 2 query parameters)
    @Query("SELECT u FROM User u WHERE (LOWER(u.username) = LOWER(:usernameOrEmail) OR LOWER(u.email) = LOWER(:usernameOrEmail)) AND u.tenantId = :tenantId")
    Optional<User> findByUsernameOrEmailAndTenantId(@Param("usernameOrEmail") String usernameOrEmail, @Param("tenantId") String tenantId);

    // ✅ FIND USER BY EMAIL (for admin operations)
    Optional<User> findByEmail(String email);

    // ✅ CHECKS for registration/validation
    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByEmailIgnoreCase(String email);
}