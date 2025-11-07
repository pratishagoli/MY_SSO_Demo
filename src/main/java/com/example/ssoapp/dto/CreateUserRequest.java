package com.example.ssoapp.dto;

public class CreateUserRequest {
    private String username;
    private String email;
    private String password; // Required for creation
    private String role;     // To set the initial role

    // Getters and Setters (omitted for brevity, but you must include them)
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
}