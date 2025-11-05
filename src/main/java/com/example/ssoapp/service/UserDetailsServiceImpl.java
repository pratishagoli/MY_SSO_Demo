package com.example.ssoapp.service;

import com.example.ssoapp.model.User;
import com.example.ssoapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Collection;

/**
 * Implements Spring Security's UserDetailsService interface.
 * This class is crucial for handling local form-based authentication.
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    /**
     * Loads the user details from the database based on the input (username or email)
     * provided in the login form.
     */
    @Override
    public UserDetails loadUserByUsername(String input) throws UsernameNotFoundException {

        // 1. Find the user by either username or email (using your custom repository method)
        User user = userRepository.findByUsernameOrEmail(input, input)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found with username/email: " + input));

        // 2. Check if user is a LOCAL user (organic login only for LOCAL users)
        if (user.getProvider() != com.example.ssoapp.model.AuthProvider.LOCAL) {
            throw new UsernameNotFoundException("User found but is not a local user. Please use SSO login.");
        }

        // 3. Check if user has a password (LOCAL users must have a password)
        if (user.getPassword() == null || user.getPassword().trim().isEmpty()) {
            throw new UsernameNotFoundException("User found but has no password set. Please reset your password.");
        }

        // 4. Prepare the user's role/authority (e.g., "ADMIN" or "USER")
        Collection<? extends GrantedAuthority> authorities =
                Collections.singletonList(new SimpleGrantedAuthority(user.getRole()));

        // 5. Return Spring Security's built-in UserDetails implementation,
        // passing the HASHED password for validation.
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),      // Principal name
                user.getPassword(),      // Must be the HASHED password from the DB
                authorities              // Roles/Permissions
        );
    }
}