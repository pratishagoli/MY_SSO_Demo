package com.example.ssoapp.controller;

import com.example.ssoapp.model.User;
import com.example.ssoapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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
}