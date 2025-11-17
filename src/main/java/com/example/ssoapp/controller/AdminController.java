package com.example.ssoapp.controller;

import com.example.ssoapp.dto.CreateUserRequest;
import com.example.ssoapp.model.AuthProvider;
import com.example.ssoapp.model.Role;
import com.example.ssoapp.model.User;
import com.example.ssoapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * REST Controller for Admin-level user management operations.
 * Requires 'TENANT_ADMIN' or 'SUPERADMIN' authority.
 */
@RestController
@RequestMapping("/api/admin/users")
// NOTE: Authorization is handled in WebSecurityConfig by checking ROLE_TENANT_ADMIN/ROLE_SUPERADMIN
public class AdminController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public AdminController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Helper method to safely convert String role to Role Enum
    private Role getRoleFromString(String roleString) {
        if (roleString == null) {
            return Role.USER;
        }
        try {
            // Updated to check against our new set of roles
            return Role.valueOf(roleString.toUpperCase());
        } catch (IllegalArgumentException e) {
            return Role.USER;
        }
    }

    // The PUT request to update a user (No changes needed here)
    @PutMapping("/{id}")
    public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody Map<String, String> updates) {
        // ... (existing logic for updateUser remains the same)
        String userIdFromBody = updates.get("id");
        if (userIdFromBody != null && !userIdFromBody.equals(id.toString())) {
            return new ResponseEntity<>("User ID mismatch in request.", HttpStatus.BAD_REQUEST);
        }

        Optional<User> userOptional = userRepository.findById(id);
        if (userOptional.isEmpty()) {
            return new ResponseEntity<>("User not found.", HttpStatus.NOT_FOUND);
        }

        User user = userOptional.get();

        // Apply updates from the request body
        String newUsername = updates.get("username");
        String newEmail = updates.get("email");
        String newRoleString = updates.get("role");
        String userType = updates.get("userType");

        // 🚀 MULTITENANCY FIX: Use the Role Enum
        Role newRole = getRoleFromString(newRoleString);


        // For SSO users, only allow role changes, not email/username (they come from provider)
        if ("sso".equals(userType)) {
            // Only update role for SSO users
            if (newRole != Role.USER && newRole != Role.TENANT_ADMIN && newRole != Role.SUPERADMIN) {
                return new ResponseEntity<>("Invalid role value. Must be USER, TENANT_ADMIN, or SUPERADMIN.", HttpStatus.BAD_REQUEST);
            }
            if (newRole != user.getRole()) {
                user.setRole(newRole);
            }
        } else {
            // For native users, allow all updates
            if (newUsername != null && !newUsername.trim().isEmpty()) {
                user.setUsername(newUsername.trim());
            }

            if (newEmail != null && !newEmail.trim().isEmpty()) {
                // Optional: Add email format and uniqueness validation here
                user.setEmail(newEmail.trim());
            }

            // 🚀 MULTITENANCY FIX: Use the Role Enum
            if (newRole != Role.USER && newRole != Role.TENANT_ADMIN && newRole != Role.SUPERADMIN) {
                return new ResponseEntity<>("Invalid role value. Must be USER, TENANT_ADMIN, or SUPERADMIN.", HttpStatus.BAD_REQUEST);
            }
            if (newRole != user.getRole()) {
                user.setRole(newRole);
            }
        }

        // Save the updated user to the database (Hibernate filter ensures data isolation)
        userRepository.save(user);

        return new ResponseEntity<>("User updated successfully.", HttpStatus.OK);
    }

    // The DELETE request to delete a user (No changes needed here)
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        // Find the existing user
        if (!userRepository.existsById(id)) {
            return new ResponseEntity<>("User not found.", HttpStatus.NOT_FOUND);
        }

        // Delete the user
        userRepository.deleteById(id);

        return new ResponseEntity<>("User deleted successfully.", HttpStatus.NO_CONTENT);
    }

    /**
     * POST request to create a native user by an Admin.
     * 🚀 Updated to return a JSON response object.
     */
    @PostMapping
    public ResponseEntity<?> createUser(@RequestBody CreateUserRequest createUserRequest) {
        // 1. Basic Validation
        if (createUserRequest.getEmail() == null || createUserRequest.getEmail().trim().isEmpty() ||
                createUserRequest.getPassword() == null || createUserRequest.getPassword().trim().isEmpty()) {
            return new ResponseEntity<>("Email and Password are required.", HttpStatus.BAD_REQUEST);
        }

        // 2. Check for Email Uniqueness (Hibernate filter ensures tenant isolation on query)
        if (userRepository.findByEmail(createUserRequest.getEmail()).isPresent()) {
            // NOTE: Due to the Hibernate filter, this check ensures uniqueness only within the current tenant's view.
            return new ResponseEntity<>("User with this email already exists in this tenant.", HttpStatus.CONFLICT);
        }

        // 3. Create and Populate User Model
        User user = new User();

        // Use username if provided, otherwise default to email
        String username = createUserRequest.getUsername() != null && !createUserRequest.getUsername().trim().isEmpty()
                ? createUserRequest.getUsername().trim()
                : createUserRequest.getEmail();

        user.setUsername(username);
        user.setEmail(createUserRequest.getEmail().trim());

        // *** CRUCIAL: Securely encode the password before saving ***
        user.setPassword(passwordEncoder.encode(createUserRequest.getPassword()));

        // Set role (default to USER if not specified or invalid)
        String roleString = createUserRequest.getRole();

        // 🚀 MULTITENANCY FIX: Set role using the Enum
        Role role = getRoleFromString(roleString);

        if (role == Role.SUPERADMIN) {
            // Admin cannot create a Superadmin, default to TENANT_ADMIN or USER
            role = Role.TENANT_ADMIN; // Assuming TENANT_ADMIN is the highest role an admin can assign
        }

        user.setRole(role);

        // Set provider as LOCAL (Native User)
        user.setProvider(AuthProvider.LOCAL);
        user.setProviderId(null);

        // 4. Save User (The Hibernate filter should automatically set the tenant_id on INSERT/UPDATE)
        User savedUser = userRepository.save(user); // Capture the saved user

        // 5. Return Success Response with the new user's ID
        // This makes the frontend integration cleaner.
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "message", "User created successfully.",
                "userId", savedUser.getId(),
                "email", savedUser.getEmail()
        ));
    }
    @GetMapping
    public ResponseEntity<List<User>> getAllNativeUsers() {
        // 1. Fetch all users for the current tenant (restricted by Hibernate filter)
        List<User> allUsers = userRepository.findAll();

        // 2. Filter to only include native users
        List<User> nativeUsers = allUsers.stream()
                .filter(user -> user.getProvider() == AuthProvider.LOCAL)
                .collect(Collectors.toList());

        return ResponseEntity.ok(nativeUsers);
    }
}