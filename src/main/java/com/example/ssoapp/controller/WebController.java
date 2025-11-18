package com.example.ssoapp.controller;

import com.example.ssoapp.config.TenantContext;
import com.example.ssoapp.model.AuthProvider;
import com.example.ssoapp.model.Role;
import com.example.ssoapp.model.User;
import com.example.ssoapp.repository.UserRepository;
import com.example.ssoapp.service.SsoConfigService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.hibernate.Session;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.EntityManager;

/**
 * Main web controller handling login, signup, dashboard routing, and user registration.
 * Supports multi-tenant architecture with role-based access control.
 */
@Controller
public class WebController {

    private static final Logger logger = LoggerFactory.getLogger(WebController.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private SsoConfigService ssoConfigService;

    @PersistenceContext
    private EntityManager entityManager;

    // ============================================================
    // ROOT ROUTE - Home Page
    // ============================================================

    /**
     * Root route handler - redirects authenticated users to dashboard,
     * unauthenticated users to login page.
     */
    public WebController(UserRepository userRepository,
                         PasswordEncoder passwordEncoder,
                         SsoConfigService ssoConfigService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.ssoConfigService = ssoConfigService;
    }

    @GetMapping("/")
    public String homePage() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // Check if user is authenticated (and not anonymous)
        if (auth != null && auth.isAuthenticated() &&
                !auth.getAuthorities().stream()
                        .anyMatch(a -> a.getAuthority().equals("ROLE_ANONYMOUS"))) {

            logger.debug("Authenticated user accessing root, redirecting to dashboard");
            return "redirect:/dashboard";
        }

        logger.debug("Unauthenticated user accessing root, redirecting to login");
        return "redirect:/login";
    }

    // ============================================================
    // LOGIN PAGE
    // ============================================================

    /**
     * Displays the login page with tenant-aware SSO options.
     * SuperAdmin context: No SSO buttons shown
     * Tenant context: SSO buttons shown based on tenant's enabled configs
     */
    @GetMapping("/login")
    public String loginPage(HttpServletRequest request, Model model) {
        // Add CSRF token to model
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (token != null) {
            model.addAttribute("_csrf", token);
        }

        // Determine if this is a tenant-specific login or SuperAdmin login
        String tenantId = TenantContext.getCurrentTenantId();
        boolean isTenantLogin = (tenantId != null && !tenantId.isEmpty());

        logger.debug("Login page accessed - Tenant context: {}",
                isTenantLogin ? "Tenant ID " + tenantId : "SuperAdmin");

        model.addAttribute("isTenantLogin", isTenantLogin);

        if (isTenantLogin) {
            // Tenant-specific login - check which SSO methods are enabled
            try {
                boolean jwtEnabled = ssoConfigService.isSsoEnabled("JWT");
                boolean oidcEnabled = ssoConfigService.isSsoEnabled("OIDC");
                boolean samlEnabled = ssoConfigService.isSsoEnabled("SAML");

                model.addAttribute("jwtEnabled", jwtEnabled);
                model.addAttribute("oidcEnabled", oidcEnabled);
                model.addAttribute("samlEnabled", samlEnabled);

                logger.debug("SSO options for tenant {}: JWT={}, OIDC={}, SAML={}",
                        tenantId, jwtEnabled, oidcEnabled, samlEnabled);
            } catch (Exception e) {
                logger.error("Error fetching SSO config for tenant {}: {}", tenantId, e.getMessage());
                // Default to disabled if there's an error
                model.addAttribute("jwtEnabled", false);
                model.addAttribute("oidcEnabled", false);
                model.addAttribute("samlEnabled", false);
            }
        } else {
            // SuperAdmin login - NO SSO options available
            model.addAttribute("jwtEnabled", false);
            model.addAttribute("oidcEnabled", false);
            model.addAttribute("samlEnabled", false);
        }

        return "login";
    }

    // ============================================================
    // SIGNUP PAGE
    // ============================================================

    /**
     * Displays the user registration/signup page.
     */
    @GetMapping("/signup")
    public String signupPage() {
        logger.debug("Signup page accessed");
        return "signup";
    }

    // ============================================================
    // USER REGISTRATION
    // ============================================================

    /**
     * Handles user registration (signup form submission).
     * Creates a new LOCAL user account with tenant context if available.
     *
     * @param username User's chosen username
     * @param email User's email address (must be unique within tenant)
     * @param password User's password (min 6 characters)
     * @return ResponseEntity with success/error message
     */
    @PostMapping("/register-user")
    public ResponseEntity<String> registerUser(
            @RequestParam("username") String username,
            @RequestParam("email") String email,
            @RequestParam("password") String password
    ) {
        logger.info("User registration attempt - Email: {}, Username: {}", email, username);

        try {
            // Validate input fields
            if (username == null || username.trim().isEmpty()) {
                logger.warn("Registration failed: Username is empty");
                return ResponseEntity.badRequest().body("Username is required.");
            }

            if (email == null || email.trim().isEmpty()) {
                logger.warn("Registration failed: Email is empty");
                return ResponseEntity.badRequest().body("Email is required.");
            }

            if (password == null || password.length() < 6) {
                logger.warn("Registration failed: Password too short");
                return ResponseEntity.badRequest().body("Password must be at least 6 characters.");
            }

            // Get tenant context
            String tenantIdString = TenantContext.getCurrentTenantId();
            Long tenantId = null;

            if (tenantIdString != null && !tenantIdString.isEmpty()) {
                try {
                    tenantId = Long.parseLong(tenantIdString);
                    logger.debug("Registration within tenant context: {}", tenantId);
                } catch (NumberFormatException e) {
                    logger.error("Invalid tenant ID format: {}", tenantIdString);
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body("Invalid tenant context.");
                }
            } else {
                // Registration without tenant context (standalone/development mode)
                logger.warn("User registration without tenant context - this may not be intended");
            }

            // Check if email already exists (tenant-aware due to Hibernate filter)
            if (userRepository.findByEmail(email.trim()).isPresent()) {
                logger.warn("Registration failed: Email already exists - {}", email);
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body("Email already in use.");
            }

            // Check if username already exists (optional uniqueness check)
            if (userRepository.existsByUsername(username.trim())) {
                logger.warn("Registration failed: Username already exists - {}", username);
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body("Username already taken.");
            }

            // Create new user
            User newUser = new User();
            newUser.setUsername(username.trim());
            newUser.setEmail(email.trim().toLowerCase());
            newUser.setPassword(passwordEncoder.encode(password));
            newUser.setProvider(AuthProvider.LOCAL);
            newUser.setRole(Role.USER); // Default role for self-registered users
            newUser.setTenantId(tenantId); // Set tenant ID (null for no-tenant context)

            // Save user to database
            User savedUser = userRepository.save(newUser);

            logger.info("User registered successfully - ID: {}, Email: {}, Tenant: {}",
                    savedUser.getId(), savedUser.getEmail(), tenantId);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body("User successfully registered.");

        } catch (Exception e) {
            logger.error("Registration failed for email {}: {}", email, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Registration failed due to server error.");
        }
    }

    // ============================================================
    // DASHBOARD ROUTING
    // ============================================================

    /**
     * Main dashboard route - intelligently routes users based on their role:
     * - SUPERADMIN → /superadmin/dashboard
     * - TENANT_ADMIN → /admindashboard (with tenant filtering)
     * - USER → /dashboard (standard user dashboard)
     *
     * Supports multiple authentication principals:
     * - Form login (UserDetails)
     * - OAuth2/OIDC (OAuth2User)
     * - SAML (Saml2AuthenticatedPrincipal)
     */
    @GetMapping("/dashboard")
    public String dashboardPage(Model model, @AuthenticationPrincipal Object principal) {
        logger.debug("Dashboard accessed by principal type: {}",
                principal != null ? principal.getClass().getSimpleName() : "null");

        String username = null;
        String email = null;
        String role = "";

        // Extract user information based on authentication type
        if (principal instanceof UserDetails) {
            // Form login or JWT authentication
            UserDetails userDetails = (UserDetails) principal;
            username = userDetails.getUsername();

            // Extract role (first authority, stripped of ROLE_ prefix)
            role = userDetails.getAuthorities().stream()
                    .findFirst()
                    .map(a -> a.getAuthority().replace("ROLE_", ""))
                    .orElse("");

            logger.debug("UserDetails authentication - Username: {}, Role: {}", username, role);

        } else if (principal instanceof OAuth2User) {
            // OAuth2/OIDC authentication
            OAuth2User oauth2User = (OAuth2User) principal;

            // Try multiple common attribute names for username
            username = oauth2User.getAttribute("name");
            if (username == null) username = oauth2User.getAttribute("login");
            if (username == null) username = oauth2User.getAttribute("preferred_username");
            if (username == null) username = oauth2User.getName();

            email = oauth2User.getAttribute("email");

            logger.debug("OAuth2 authentication - Username: {}, Email: {}", username, email);

        } else if (principal instanceof Saml2AuthenticatedPrincipal) {
            // SAML authentication
            Saml2AuthenticatedPrincipal samlPrincipal = (Saml2AuthenticatedPrincipal) principal;
            username = samlPrincipal.getName();

            // Try to extract email from SAML attributes
            email = samlPrincipal.getFirstAttribute("email");
            if (email == null) email = samlPrincipal.getFirstAttribute("mail");

            logger.debug("SAML authentication - Username: {}, Email: {}", username, email);

        } else if (principal != null) {
            // Fallback for unknown principal types
            username = principal.toString();
            logger.warn("Unknown principal type: {}", principal.getClass().getName());

        } else {
            // No authentication - redirect to login
            logger.warn("Dashboard accessed without authentication");
            return "redirect:/login";
        }

        // Add username to model for display
        model.addAttribute("username", username != null ? username : "User");

        // Route based on role
        if ("SUPERADMIN".equals(role)) {
            logger.info("Routing SUPERADMIN to superadmin dashboard: {}", username);
            return "redirect:/superadmin/dashboard";
        } else if ("TENANT_ADMIN".equals(role)) {
            logger.info("Routing TENANT_ADMIN to admin dashboard: {}", username);
            return "redirect:/admindashboard";
        } else {
            // Default route for standard users
            logger.info("Routing USER to standard dashboard: {}", username);
            return "/dashboard.html"; // Renders templates/dashboard.html
        }
    }

    // ============================================================
    // ADMIN DASHBOARD (Tenant Admin)
    // ============================================================

    /**
     * Admin dashboard for Tenant Admins.
     * This route is protected by role-based security in WebSecurityConfig.
     */
    @GetMapping("/admindashboard")
    public String adminDashboard(Model model, @AuthenticationPrincipal UserDetails userDetails) {
        if (userDetails == null) {
            logger.warn("Admin dashboard accessed without authentication");
            return "redirect:/login";
        }

        String tenantId = TenantContext.getCurrentTenantId();
        logger.info("Admin dashboard accessed by {} in tenant context: {}",
                userDetails.getUsername(), tenantId);

        // ✅ CRITICAL FIX: Verify tenant context is set
        if (tenantId == null || tenantId.isEmpty()) {
            logger.error("No tenant context found for admin dashboard access");
            model.addAttribute("error", "Tenant context not found. Please contact support.");
            model.addAttribute("nativeUsers", new ArrayList<>());
            model.addAttribute("ssoUsers", new ArrayList<>());
            return "admindashboard";
        }

        try {
            // ✅ Enable Hibernate filter explicitly
            Session session = entityManager.unwrap(Session.class);
            org.hibernate.Filter filter = session.enableFilter("tenantFilter");
            filter.setParameter("tenantId", Long.valueOf(tenantId));

            logger.info("Hibernate tenant filter enabled for tenantId: {}", tenantId);

            // Fetch all users - filter will automatically apply tenant restriction
            List<User> allUsers = userRepository.findAll();

            logger.info("Found {} total users for tenant {}", allUsers.size(), tenantId);

            // Separate into native and SSO users
            List<User> nativeUsers = allUsers.stream()
                    .filter(u -> u.getProvider() == AuthProvider.LOCAL)
                    .collect(Collectors.toList());

            List<User> ssoUsers = allUsers.stream()
                    .filter(u -> u.getProvider() != AuthProvider.LOCAL)
                    .collect(Collectors.toList());

            logger.info("Native users: {}, SSO users: {}", nativeUsers.size(), ssoUsers.size());

            model.addAttribute("nativeUsers", nativeUsers);
            model.addAttribute("ssoUsers", ssoUsers);
            model.addAttribute("tenantId", tenantId);

        } catch (Exception e) {
            logger.error("Error fetching users for admin dashboard: {}", e.getMessage(), e);
            model.addAttribute("error", "Failed to load user list.");
            model.addAttribute("nativeUsers", new ArrayList<>());
            model.addAttribute("ssoUsers", new ArrayList<>());
        }

        return "admindashboard";
    }
}