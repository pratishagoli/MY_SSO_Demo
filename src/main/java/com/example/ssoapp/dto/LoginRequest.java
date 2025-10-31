package com.example.ssoapp.dto;

import jakarta.validation.constraints.NotBlank;

public class LoginRequest {
    @NotBlank
    private String username;

    @NotBlank
    private String password;

    // --- Getters and Setters ---
    // (These were missing their method bodies)

    public String getUsername() {
        return this.username; // FIX: Added return statement
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return this.password; // FIX: Added return statement
    }

    public void setPassword(String password) {
        this.password = password;
    }
}