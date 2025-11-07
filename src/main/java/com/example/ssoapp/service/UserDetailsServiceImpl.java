package com.example.ssoapp.service;

import com.example.ssoapp.model.User;
// import com.example.ssoapp.model.Role; // This import is not used, can be removed
import com.example.ssoapp.repository.UserRepository;
import com.example.ssoapp.config.TenantContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Collection;
import java.util.Optional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String input) throws UsernameNotFoundException {

        User user = null;
        String currentTenantId = TenantContext.getCurrentTenantId();

        // 🧩 1️⃣ SuperAdmin login (no tenant)
        if (currentTenantId == null || currentTenantId.isEmpty()) {
            Optional<User> superAdminOpt = userRepository.findSuperAdminByEmail(input);
            if (superAdminOpt.isPresent()) {
                user = superAdminOpt.get();
            }
        }

        // 🧩 2️⃣ Tenant-specific login
        if (user == null && currentTenantId != null && !currentTenantId.isEmpty()) {

            // ✅ FIXED: Changed from (input, input, currentTenantId) to (input, currentTenantId)
            // This now matches the 2 arguments in your UserRepository method
            Optional<User> tenantUserOpt = userRepository.findByUsernameOrEmailAndTenantId(input, currentTenantId);

            if (tenantUserOpt.isPresent()) {
                user = tenantUserOpt.get();
            } else {
                throw new UsernameNotFoundException("User not found in tenant '" + currentTenantId + "': " + input);
            }
        }

        // 🧩 3️⃣ Final validation
        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + input);
        }

        // 🧩 4️⃣ Build user authorities from Role Enum
        Collection<? extends GrantedAuthority> authorities =
                Collections.singletonList(new SimpleGrantedAuthority(user.getRole().withPrefix()));

        // 🧩 5️⃣ Return Spring Security User object
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),   // use email for username
                user.getPassword(),
                authorities
        );
    }
}