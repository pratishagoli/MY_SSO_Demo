package com.example.ssoapp.controller;

import com.example.ssoapp.model.AuthProvider;
import com.example.ssoapp.model.User;
import com.example.ssoapp.model.Role; // 🚀 NEW IMPORT
import com.example.ssoapp.repository.UserRepository;
import com.example.ssoapp.service.JwtValidationService;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository; // Used for the constant key
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/auth/jwt")
public class JwtController {

    private static final Logger logger = LoggerFactory.getLogger(JwtController.class);

    @Autowired
    private JwtValidationService jwtValidationService;

    @Autowired
    private UserRepository userRepository;

    public JwtController(JwtValidationService jwtValidationService, UserRepository userRepository) {
        this.jwtValidationService = jwtValidationService;
        this.userRepository = userRepository;
    }
    @GetMapping("callback") // Use the actual callback path
    public void handleJwtCallback(@RequestParam("id_token") String jwt, // Or however you receive the token
                                  HttpServletRequest request,
                                  HttpServletResponse response) throws Exception {

        try {
            // 1. Validate the JWT and extract claims
            Map<String, Object> claims = jwtValidationService.validateToken(jwt);

            String email = (String) claims.get("email");
            String username = (String) claims.get("username");
            String sub = (String) claims.get("sub");

            // 2. Register or retrieve user (use the method from your filter)
            User user = registerOrRetrieveUser(email, username, sub);

            // 3. Manually create and set authentication in SecurityContext

            // Get user's authorities based on role (assuming role is set by registerOrRetrieveUser or is pre-existing)
            String roleName = user.getRole() != null ? user.getRole().name() : Role.USER.name();

            UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                    user.getUsername(),
                    "", // No password needed for JWT authentication
                    java.util.Collections.singletonList(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_" + roleName))
            );

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Set in the holder for the current request
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // 🚀 CRITICAL FIX: Explicitly save the context to the session using the constant 🚀
            HttpSession session = request.getSession(true);
            session.setAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, // 👈 Using the constant
                    SecurityContextHolder.getContext()
            );

            logger.info("Authentication context saved for user: {}", username);

            // Check if this is a test flow from session
            Boolean testMode = (Boolean) request.getSession().getAttribute("sso_test_mode");
            String testType = (String) request.getSession().getAttribute("sso_test_type");

            if (Boolean.TRUE.equals(testMode) && "JWT".equals(testType)) {
                // Store JWT test result in session for modal popup
                Map<String, Object> testResult = new java.util.HashMap<>();
                testResult.put("testType", "JWT");
                testResult.put("testStatus", "success");
                testResult.put("token", jwt);

                // Decode JWT attributes
                Map<String, Object> attributes = new java.util.HashMap<>(claims);
                testResult.put("attributes", attributes);

                request.getSession().setAttribute("sso_test_result", testResult);
                request.getSession().removeAttribute("sso_test_mode");
                request.getSession().removeAttribute("sso_test_type");

                // Restore admin session
                restoreAdminSessionForJwt(request);

                // Redirect back to config page - modal will show result
                response.sendRedirect("/admin/sso/config?test=success");
                return;
            }

            // 4. Redirect to the protected resource
            response.sendRedirect("/dashboard");

        } catch (Exception e) {
            // Log the error and redirect to an error page or login page
            logger.error("SSO callback authentication failed: {}", e.getMessage());
            response.sendRedirect("/login?error=auth_failed");
        }
    }

    private User registerOrRetrieveUser(String email, String username, String providerId) {
        // Find user, tenant-aware via Hibernate filter
        Optional<User> existingUser = userRepository.findByEmail(email);

        if (existingUser.isPresent()) {
            User user = existingUser.get();
            logger.info("User already exists: {} (Role: {})", email, user.getRole().name());

            // Ensure the user has a role set (in case of legacy/initial data)
            if (user.getRole() == null) {
                user.setRole(Role.USER);
                user = userRepository.saveAndFlush(user);
            }
            return user;
        }

        logger.info("Creating new user from JWT: {}", email);

        User newUser = new User();
        newUser.setEmail(email);
        newUser.setUsername(username);
        newUser.setProviderId(providerId);
        newUser.setProvider(AuthProvider.MINIORANGE);
        newUser.setPassword(null);

        // 🚀 FIX APPLIED HERE: Use Role Enum object
        newUser.setRole(Role.USER); // Default role for SSO users

        return userRepository.saveAndFlush(newUser);
    }

    private void restoreAdminSessionForJwt(HttpServletRequest request) {
        // Restore admin authentication after test
        org.springframework.security.core.Authentication adminAuth =
                (org.springframework.security.core.Authentication) request.getSession().getAttribute("admin_test_principal");
        if (adminAuth != null) {
            org.springframework.security.core.context.SecurityContext securityContext =
                    org.springframework.security.core.context.SecurityContextHolder.getContext();
            securityContext.setAuthentication(adminAuth);

            HttpSession session = request.getSession();
            session.setAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                    securityContext
            );

            request.getSession().removeAttribute("admin_test_principal");
            request.getSession().removeAttribute("admin_test_authorities");
            logger.info("Admin session restored after JWT test");
        }
    }
}