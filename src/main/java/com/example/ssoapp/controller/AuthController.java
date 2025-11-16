package com.example.ssoapp.controller;

import com.example.ssoapp.dto.SignupRequest;
import com.example.ssoapp.service.AuthService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST Controller for authentication endpoints (signup, login, etc.)
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthService authService;

    public  AuthController(AuthService authService){
        this.authService=authService;
    }
    /**
     * Endpoint for local user signup
     */
    @PostMapping(path = "/signup",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {

        logger.info("Signup request received for username: {}", signUpRequest.getUsername());

        // Check if username is taken
        if (authService.existsByUsername(signUpRequest.getUsername())) {
            logger.warn("Signup failed: Username already taken - {}", signUpRequest.getUsername());
            return ResponseEntity.badRequest().body("Error: Username is already taken!");
        }

        // Check if email is taken
        if (authService.existsByEmail(signUpRequest.getEmail())) {
            logger.warn("Signup failed: Email already in use - {}", signUpRequest.getEmail());
            return ResponseEntity.badRequest().body("Error: Email is already in use!");
        }

        // Register the user
        authService.registerNewUser(signUpRequest);

        return ResponseEntity.ok("User registered successfully!");
    }
}
