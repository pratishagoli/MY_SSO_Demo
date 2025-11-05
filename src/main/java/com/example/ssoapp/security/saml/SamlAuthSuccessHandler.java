package com.example.ssoapp.security.saml;

import com.example.ssoapp.model.AuthProvider;
import com.example.ssoapp.model.User;
import com.example.ssoapp.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class SamlAuthSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(SamlAuthSuccessHandler.class);

    @Autowired
    private UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        try {
            logger.info("=== SAML AUTHENTICATION SUCCESS HANDLER CALLED ===");
            logger.info("Request URI: {}", request.getRequestURI());
            logger.info("Request Query String: {}", request.getQueryString());
            logger.info("Request Method: {}", request.getMethod());
            logger.info("Authentication principal type: {}", authentication.getPrincipal().getClass().getName());
            logger.info("Authentication authorities: {}", authentication.getAuthorities());
            logger.info("Authentication details: {}", authentication.getDetails());
            logger.info("SAML authentication successful. Processing user...");
            
            // Log all request parameters
            logger.info("Request parameters:");
            request.getParameterMap().forEach((key, values) -> 
                logger.info("  {} = {}", key, java.util.Arrays.toString(values))
            );

            Object principal = authentication.getPrincipal();
            String email = null;
            String username = null;
            String nameId = null;

            // Extract SAML attributes
            if (principal instanceof Saml2AuthenticatedPrincipal) {
                Saml2AuthenticatedPrincipal samlPrincipal = (Saml2AuthenticatedPrincipal) principal;
                
                // Get NameID first (often the email in SAML)
                nameId = samlPrincipal.getName();
                logger.info("SAML NameID: {}", nameId);
                
                // Extract email from SAML attributes - try multiple common attribute names
                email = samlPrincipal.getFirstAttribute("email");
                if (email == null || email.trim().isEmpty()) {
                    email = samlPrincipal.getFirstAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
                }
                if (email == null || email.trim().isEmpty()) {
                    email = samlPrincipal.getFirstAttribute("Email");
                }
                if (email == null || email.trim().isEmpty()) {
                    email = samlPrincipal.getFirstAttribute("mail");
                }
                
                // Extract name/username
                username = samlPrincipal.getFirstAttribute("name");
                if (username == null || username.trim().isEmpty()) {
                    username = samlPrincipal.getFirstAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name");
                }
                if (username == null || username.trim().isEmpty()) {
                    username = samlPrincipal.getFirstAttribute("Name");
                }
                if (username == null || username.trim().isEmpty()) {
                    username = samlPrincipal.getFirstAttribute("displayName");
                }

                logger.info("SAML attributes extracted - Email: {}, Username: {}, NameID: {}", email, username, nameId);

                // If email is still null, try using NameID (which is often email in SAML)
                if ((email == null || email.trim().isEmpty()) && nameId != null && nameId.contains("@")) {
                    email = nameId;
                    logger.info("Using NameID as email: {}", email);
                }

                // If email is still null but NameID exists, use it anyway
                if ((email == null || email.trim().isEmpty()) && nameId != null && !nameId.trim().isEmpty()) {
                    email = nameId;
                    logger.info("Using NameID as email (fallback): {}", email);
                }

                // If username is still null, derive from email
                if ((username == null || username.trim().isEmpty()) && email != null && email.contains("@")) {
                    username = email.split("@")[0];
                    logger.info("Derived username from email: {}", username);
                } else if ((username == null || username.trim().isEmpty()) && email != null) {
                    username = email;
                    logger.info("Using email as username: {}", username);
                }

                // Register or retrieve user - MUST succeed before proceeding
                User user = null;
                if (email == null || email.trim().isEmpty()) {
                    logger.error("CRITICAL: No email found in SAML assertion. NameID: {}", nameId);
                    response.sendRedirect("/login?error=no_email");
                    return;
                }
                
                try {
                    user = registerOrRetrieveUser(email, username, nameId);
                    if (user == null) {
                        logger.error("CRITICAL: User registration returned null for email: {}", email);
                        response.sendRedirect("/login?error=user_creation_failed");
                        return;
                    }
                    logger.info("User processed successfully: {} (ID: {})", user.getEmail(), user.getId());

                    // Update authentication with user details and authorities
                    Collection<GrantedAuthority> authorities = new ArrayList<>(authentication.getAuthorities());

                    // Add user role as authority
                    if (user.getRole() != null) {
                        authorities.add(new SimpleGrantedAuthority(user.getRole()));
                    } else {
                        // Ensure default role is set
                        user.setRole("USER");
                        user = userRepository.save(user);
                        authorities.add(new SimpleGrantedAuthority("USER"));
                        logger.info("Set default USER role for user: {}", email);
                    }

                    // Create UserDetails for the authenticated user
                    UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                            user.getUsername() != null ? user.getUsername() : email,
                            "",
                            authorities
                    );

                    // Create new authentication with user details
                    org.springframework.security.authentication.UsernamePasswordAuthenticationToken newAuth =
                        new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            authorities
                        );
                    newAuth.setDetails(authentication.getDetails());
                    
                    // Update SecurityContext
                    SecurityContext securityContext = SecurityContextHolder.getContext();
                    securityContext.setAuthentication(newAuth);
                    
                    // Save to session
                    HttpSession session = request.getSession(true);
                    session.setAttribute(
                        HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                        securityContext
                    );
                    
                    logger.info("Authentication context updated and saved for user: {} (ID: {})", email, user.getId());
                    
                } catch (Exception e) {
                    logger.error("CRITICAL: Failed to register/retrieve user for email: {}", email, e);
                    response.sendRedirect("/login?error=user_creation_failed");
                    return;
                }

                // Log all available attributes for debugging
                logger.info("Available SAML attributes:");
                samlPrincipal.getAttributes().forEach((key, value) -> 
                    logger.info("  {} = {}", key, value)
                );
                
                // Check if this is a test flow from session
                Boolean testMode = (Boolean) request.getSession().getAttribute("sso_test_mode");
                String testType = (String) request.getSession().getAttribute("sso_test_type");
                if (Boolean.TRUE.equals(testMode) && "SAML".equals(testType)) {
                    // Store SAML attributes in session for modal popup
                    Map<String, Object> samlAttributes = new HashMap<>();
                    samlAttributes.put("NameID", samlPrincipal.getName());
                    samlPrincipal.getAttributes().forEach((key, value) -> 
                        samlAttributes.put(key, value)
                    );
                    
                    // Store test result in session
                    Map<String, Object> testResult = new HashMap<>();
                    testResult.put("testType", "SAML");
                    testResult.put("testStatus", "success");
                    testResult.put("attributes", samlAttributes);
                    
                    // Store assertion in DB for debugging
                    try {
                        String assertionJson = new ObjectMapper().writeValueAsString(samlAttributes);
                        request.getSession().setAttribute("saml_assertion_to_store", assertionJson);
                        logger.info("SAML assertion prepared for storage in DB");
                    } catch (Exception e) {
                        logger.warn("Failed to prepare SAML assertion for DB: {}", e.getMessage());
                    }
                    
                    request.getSession().setAttribute("sso_test_result", testResult);
                    request.getSession().removeAttribute("sso_test_mode");
                    request.getSession().removeAttribute("sso_test_type");
                    
                    // Restore admin session
                    restoreAdminSession(request);
                    
                    // Redirect back to config page - modal will show result
                    response.sendRedirect("/admin/sso/config?test=success");
                    return;
                }
                
                // Ensure user is not null before redirect
                if (user == null) {
                    logger.error("CRITICAL: User is null after processing. Cannot proceed.");
                    response.sendRedirect("/login?error=authentication_failed");
                    return;
                }
                
                // Determine redirect URL based on user role
                String targetUrl = "/dashboard";
                if ("ADMIN".equals(user.getRole())) {
                    targetUrl = "/admindashboard";
                    logger.info("SAML user {} (ID: {}) is ADMIN, redirecting to: {}", email, user.getId(), targetUrl);
                } else {
                    logger.info("SAML user {} (ID: {}) is USER, redirecting to: {}", email, user.getId(), targetUrl);
                }
                
                response.sendRedirect(targetUrl);
                return;
            } else {
                logger.error("CRITICAL: Principal is not Saml2AuthenticatedPrincipal!");
                logger.error("Principal type: {}", principal.getClass().getName());
                logger.error("Principal toString: {}", principal.toString());
                
                // Try to extract from authentication object anyway
                if (principal instanceof org.springframework.security.core.userdetails.UserDetails) {
                    logger.warn("Principal is UserDetails, attempting to extract info...");
                    org.springframework.security.core.userdetails.UserDetails userDetails = 
                        (org.springframework.security.core.userdetails.UserDetails) principal;
                    logger.info("UserDetails username: {}", userDetails.getUsername());
                }
            }

            // Fallback redirect
            logger.warn("Falling back to dashboard redirect - SAML authentication may have failed");
            response.sendRedirect("/dashboard");
        
        } catch (Exception e) {
            logger.error("CRITICAL: Exception in SAML success handler", e);
            logger.error("Exception type: {}", e.getClass().getName());
            logger.error("Exception message: {}", e.getMessage());
            if (e.getCause() != null) {
                logger.error("Exception cause: {}", e.getCause().getMessage());
            }
            // Redirect to login with error - this will be caught by failure handler
            response.sendRedirect("/login?error=saml_failed&details=" + 
                java.net.URLEncoder.encode(e.getMessage() != null ? e.getMessage() : "Handler exception", "UTF-8"));
        }
    }

    private void restoreAdminSession(HttpServletRequest request) {
        // Restore admin authentication after test
        org.springframework.security.core.Authentication adminAuth = 
            (org.springframework.security.core.Authentication) request.getSession().getAttribute("admin_test_principal");
        if (adminAuth != null) {
            SecurityContext securityContext = SecurityContextHolder.getContext();
            securityContext.setAuthentication(adminAuth);
            
            HttpSession session = request.getSession();
            session.setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                securityContext
            );
            
            request.getSession().removeAttribute("admin_test_principal");
            request.getSession().removeAttribute("admin_test_authorities");
            logger.info("Admin session restored after SAML test");
        }
    }

    @Transactional(rollbackFor = Exception.class)
    private User registerOrRetrieveUser(String email, String username, String providerId) {
        logger.info("Checking if user exists: {}", email);

        Optional<User> existingUser = userRepository.findByEmail(email);

        if (existingUser.isPresent()) {
            User user = existingUser.get();
            logger.info("User already exists - ID: {}, Email: {}, Role: {}", user.getId(), user.getEmail(), user.getRole());
            
            // Ensure role is set if missing
            if (user.getRole() == null || user.getRole().trim().isEmpty()) {
                user.setRole("USER");
                user = userRepository.saveAndFlush(user);
                logger.info("Updated user role to USER for existing user: {}", email);
            }
            
            return user;
        }

        logger.info("NEW USER - Creating in database... Email: {}, Username: {}", email, username);

        User newUser = new User();
        newUser.setEmail(email.trim());
        
        // Ensure username is set
        if (username == null || username.trim().isEmpty()) {
            if (email != null && email.contains("@")) {
                username = email.split("@")[0];
            } else {
                username = email;
            }
        }
        newUser.setUsername(username.trim());
        newUser.setProviderId(providerId);
        newUser.setProvider(AuthProvider.MINIORANGE);
        newUser.setPassword(null); // SSO users don't have passwords
        newUser.setRole("USER"); // Default role - MUST be set

        try {
            User saved = userRepository.saveAndFlush(newUser);
            logger.info("SUCCESS - User saved with ID: {}, Email: {}, Username: {}, Role: {}", 
                    saved.getId(), saved.getEmail(), saved.getUsername(), saved.getRole());
            
            // Verify the user was actually saved
            Optional<User> verification = userRepository.findById(saved.getId());
            if (verification.isEmpty()) {
                logger.error("CRITICAL: User was saved but cannot be retrieved! ID: {}", saved.getId());
                throw new RuntimeException("User verification failed after save");
            }
            
            return saved;
        } catch (Exception e) {
            logger.error("FAILED to save user! Email: {}, Error: {}", email, e.getMessage(), e);
            throw new RuntimeException("Failed to create user in database: " + e.getMessage(), e);
        }
    }
}

