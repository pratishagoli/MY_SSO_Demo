package com.example.ssoapp.controller;

import com.example.ssoapp.dto.CreateUserRequest;
import com.example.ssoapp.model.AuthProvider; // Ensure this import is correct
import com.example.ssoapp.model.User;
import com.example.ssoapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder; // *** NEW IMPORT ***
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

/**
 * REST Controller for Admin-level user management operations.
 * Requires 'ADMIN' authority, as configured in WebSecurityConfig.
 */
@RestController
@RequestMapping("/api/admin/users")
public class AdminController {

    @Autowired
    private UserRepository userRepository;

    // *** NEW: PasswordEncoder dependency is required for secure password hashing ***
    @Autowired
    private PasswordEncoder passwordEncoder;

    // The PUT request to update a user
    @PutMapping("/{id}")
    public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody Map<String, String> updates) {
        // Ensure the ID in the path matches the ID in the body (optional check)
        String userIdFromBody = updates.get("id");
        if (userIdFromBody != null && !userIdFromBody.equals(id.toString())) {
            return new ResponseEntity<>("User ID mismatch in request.", HttpStatus.BAD_REQUEST);
        }

        // Find the existing user
        Optional<User> userOptional = userRepository.findById(id);
        if (userOptional.isEmpty()) {
            return new ResponseEntity<>("User not found.", HttpStatus.NOT_FOUND);
        }

        User user = userOptional.get();

        // Apply updates from the request body
        String newUsername = updates.get("username");
        String newEmail = updates.get("email");
        String newRole = updates.get("role");
        String userType = updates.get("userType");

        // For SSO users, only allow role changes, not email/username (they come from provider)
        if ("sso".equals(userType)) {
            // Only update role for SSO users
            if (newRole != null && (newRole.equalsIgnoreCase("USER") || newRole.equalsIgnoreCase("ADMIN"))) {
                user.setRole(newRole.toUpperCase());
            } else if (newRole != null && !newRole.trim().isEmpty()) {
                return new ResponseEntity<>("Invalid role value. Must be USER or ADMIN.", HttpStatus.BAD_REQUEST);
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

            if (newRole != null && (newRole.equalsIgnoreCase("USER") || newRole.equalsIgnoreCase("ADMIN"))) {
                user.setRole(newRole.toUpperCase());
            } else if (newRole != null && !newRole.trim().isEmpty()) {
                return new ResponseEntity<>("Invalid role value. Must be USER or ADMIN.", HttpStatus.BAD_REQUEST);
            }
        }

        // Save the updated user to the database
        userRepository.save(user);

        return new ResponseEntity<>("User updated successfully.", HttpStatus.OK);
    }

    // The DELETE request to delete a user
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        // Find the existing user
        if (!userRepository.existsById(id)) {
            return new ResponseEntity<>("User not found.", HttpStatus.NOT_FOUND);
        }

        // Optional: Prevent deleting the currently logged-in admin user

        // Delete the user
        userRepository.deleteById(id);

        return new ResponseEntity<>("User deleted successfully.", HttpStatus.NO_CONTENT);
    }

    /**
     * NEW: POST request to create a native user by an Admin.
     */
    @PostMapping
    public ResponseEntity<?> createUser(@RequestBody CreateUserRequest createUserRequest) {
        // 1. Basic Validation
        if (createUserRequest.getEmail() == null || createUserRequest.getEmail().trim().isEmpty() ||
                createUserRequest.getPassword() == null || createUserRequest.getPassword().trim().isEmpty()) {
            return new ResponseEntity<>("Email and Password are required.", HttpStatus.BAD_REQUEST);
        }

        // 2. Check for Email Uniqueness (Requires findByEmail in UserRepository)
        // If findByEmail returns an Optional<User>, checking .isPresent() is correct.
        if (userRepository.findByEmail(createUserRequest.getEmail()).isPresent()) {
            return new ResponseEntity<>("User with this email already exists.", HttpStatus.CONFLICT);
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
        String role = createUserRequest.getRole();
        if (role != null && (role.equalsIgnoreCase("USER") || role.equalsIgnoreCase("ADMIN"))) {
            user.setRole(role.toUpperCase());
        } else {
            user.setRole("USER"); // Default to USER
        }

        // Set provider as LOCAL (Native User)
        user.setProvider(AuthProvider.LOCAL); // Assumes AuthProvider.LOCAL is defined
        user.setProviderId(null);

        // 4. Save User
        userRepository.save(user);

        return new ResponseEntity<>("User created successfully.", HttpStatus.CREATED);
    }
}