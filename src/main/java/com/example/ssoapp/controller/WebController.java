package com.example.ssoapp.controller;

import com.example.ssoapp.model.AuthProvider;
import com.example.ssoapp.model.User;
import com.example.ssoapp.model.Role; // NEW IMPORT
import com.example.ssoapp.repository.UserRepository;
import com.example.ssoapp.service.SsoConfigService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import com.example.ssoapp.config.TenantContext;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;

@Controller
public class WebController {

    // --- DEPENDENCY INJECTION ---
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private SsoConfigService ssoConfigService;
    // ----------------------------

    @GetMapping("/login")
    public String loginPage(HttpServletRequest request, Model model) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (token != null) {
            model.addAttribute("_csrf", token);
        }

        // 🚀 Check if this is a tenant subdomain or SuperAdmin
        String tenantId = TenantContext.getCurrentTenantId();
        boolean isTenantLogin = (tenantId != null && !tenantId.isEmpty());

        model.addAttribute("isTenantLogin", isTenantLogin);

        if (isTenantLogin) {
            // Tenant-specific login - show SSO buttons if enabled
            model.addAttribute("jwtEnabled", ssoConfigService.isSsoEnabled("JWT"));
            model.addAttribute("oidcEnabled", ssoConfigService.isSsoEnabled("OIDC"));
            model.addAttribute("samlEnabled", ssoConfigService.isSsoEnabled("SAML"));
        } else {
            // SuperAdmin login - NO SSO buttons
            model.addAttribute("jwtEnabled", false);
            model.addAttribute("oidcEnabled", false);
            model.addAttribute("samlEnabled", false);
        }

        return "login";
    }
    @GetMapping("/signup")
    public String signupPage() {
        return "signup";
    }

    @PostMapping("/register-user")
    public ResponseEntity<String> registerUser(
            @RequestParam("username") String username,
            @RequestParam("email") String email,
            @RequestParam("password") String password
    ) {
        try {
            if (username == null || email == null || password == null || password.length() < 6) {
                return ResponseEntity.badRequest().body("Invalid input fields.");
            }
            // Note: Since we don't have TenantContext applied to /register-user yet,
            // this check is currently global. A proper implementation would check
            // uniqueness within the tenant if a tenant is resolved.
            if (userRepository.findByEmail(email).isPresent()) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already in use.");
            }

            String hashedPassword = passwordEncoder.encode(password);

            User newUser = new User();
            newUser.setUsername(username);
            newUser.setEmail(email);
            newUser.setPassword(hashedPassword);
            newUser.setProvider(AuthProvider.LOCAL);
            newUser.setRole(Role.USER); // Set default role to standard USER

            // ⚠️ TEMPORARY: Since this is a regular user registration,
            // we are not assigning a tenantId here.
            // In a real flow, this should happen on a TENANT subdomain.
            // For now, we rely on the TenantFilter to set the context when accessing this path.
            // We'll update this when the TenantFilter is in place.
            newUser.setTenantId(null);

            userRepository.save(newUser);

            return ResponseEntity.status(HttpStatus.CREATED).body("User successfully registered.");

        } catch (Exception e) {
            System.err.println("Registration failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Registration failed due to server error.");
        }
    }


    @GetMapping("/dashboard")
    public String dashboardPage(Model model, @AuthenticationPrincipal Object principal) {
        String username;
        String role = ""; // Track role for routing

        if (principal instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) principal;
            username = userDetails.getUsername();
            role = userDetails.getAuthorities().stream().findFirst()
                    .map(a -> a.getAuthority().replace("ROLE_", "")).orElse("");
        } else if (principal instanceof OAuth2User) {
            // ... (SSO logic remains the same)
            username = ((OAuth2User) principal).getAttribute("name");
            if (username == null) username = ((OAuth2User) principal).getAttribute("login");
            if (username == null) username = ((OAuth2User) principal).getName();
        } else if (principal instanceof Saml2AuthenticatedPrincipal) {
            Saml2AuthenticatedPrincipal samlPrincipal = (Saml2AuthenticatedPrincipal) principal;
            username = samlPrincipal.getName();
        } else if (principal != null) {
            username = principal.toString();
        } else {
            return "redirect:/login";
        }

        model.addAttribute("username", username);

        // 🚀 FIXED LOGIC: Route based on role
        if ("SUPERADMIN".equals(role)) {
            // Redirect SUPERADMIN to its specific controller/page
            // ✅ FIXED: Corrected path from "/superadmin-dashboard" to "/superadmin/dashboard"
            return "redirect:/superadmin/dashboard";
        }

        // Standard user/tenant admin dashboard (admindashboard renamed to just 'dashboard' for simplicity)
        // Note: Tenant Admin will see a filtered dashboard automatically due to multitenancy filter/context
        return "dashboard"; // Renders src/main/resources/templates/dashboard.html
    }



    /**
     * The old /admindashboard is now unused or should be deleted.
     * The Superadmin has its own controller, and Tenant Admins use /dashboard (filtered).
     * I will delete the old /admindashboard method for production cleanliness.
     */
}