package com.example.ssoapp.service;

import com.example.ssoapp.model.User;
import com.example.ssoapp.model.Role; // NEW IMPORT
import com.example.ssoapp.repository.UserRepository;
import com.example.ssoapp.config.TenantContext; // NEW IMPORT - We'll create this later
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Collection;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    /**
     * Loads the user details from the database based on the input (username or email).
     * Now includes multitenancy logic based on TenantContext.
     */
    @Override
    public UserDetails loadUserByUsername(String input) throws UsernameNotFoundException {

        User user = null;
        String currentTenantId = TenantContext.getCurrentTenantId(); // Get current tenant ID

        // 1. SCENARIO A: SUPERADMIN login (tenantId will be null)
        if (currentTenantId == null || currentTenantId.isEmpty()) {
            // Only allow SUPERADMIN login on the main domain (localhost:8080)
            user = userRepository.findSuperAdminByEmail(input)
                    .orElse(null); // Return null if not found
        }

        // 2. SCENARIO B: TENANT USER/ADMIN login
        if (user == null && currentTenantId != null && !currentTenantId.isEmpty()) {
            // Filter by the resolved tenantId from the host/subdomain
            user = userRepository.findByUsernameOrEmailAndTenantId(input, input, currentTenantId)
                    .orElseThrow(() ->
                            new UsernameNotFoundException("User not found in tenant '" + currentTenantId + "': " + input));
        }

        // 3. FINAL CHECK: If no user found in either scenario
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + input);
        }

        // 4. Continue with standard checks
        if (user.getProvider() != com.example.ssoapp.model.AuthProvider.LOCAL) {
            throw new UsernameNotFoundException("User found but is not a local user. Please use SSO login.");
        }
        if (user.getPassword() == null || user.getPassword().trim().isEmpty()) {
            throw new UsernameNotFoundException("User found but has no password set.");
        }

        // 5. Prepare the user's role/authority
        Collection<? extends GrantedAuthority> authorities =
                Collections.singletonList(new SimpleGrantedAuthority(user.getRole().withPrefix())); // Use withPrefix()

        // 6. Return UserDetails
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                authorities
        );
    }
}