package com.example.ssoapp.controller;

import com.example.ssoapp.model.AuthProvider;
import com.example.ssoapp.model.User;
import com.example.ssoapp.repository.UserRepository;
import com.example.ssoapp.service.SsoConfigService;
import jakarta.servlet.http.HttpServletRequest; // 👈 NEW IMPORT
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
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

    @GetMapping("/")
    public String rootPage() {
        // Redirect root path to login
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String loginPage(HttpServletRequest request, Model model) { // 👈 ADDED REQUEST & MODEL
        // Explicitly adding CSRF token to model for form rendering (optional but safe)
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (token != null) {
            model.addAttribute("_csrf", token);
        }
        
        // Add SSO configuration status to model
        model.addAttribute("jwtEnabled", ssoConfigService.isSsoEnabled("JWT"));
        model.addAttribute("oidcEnabled", ssoConfigService.isSsoEnabled("OIDC"));
        model.addAttribute("samlEnabled", ssoConfigService.isSsoEnabled("SAML"));
        
        return "login"; // Renders src/main/resources/templates/login.html
    }

    @GetMapping("/signup")
    public String signupPage() {
        return "signup"; // Renders src/main/resources/templates/signup.html
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
            if (userRepository.findByEmail(email).isPresent()) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already in use.");
            }

            String hashedPassword = passwordEncoder.encode(password);

            User newUser = new User();
            newUser.setUsername(username);
            newUser.setEmail(email);
            newUser.setPassword(hashedPassword);
            newUser.setProvider(AuthProvider.LOCAL);
            newUser.setRole("USER"); // Set default role to "USER"

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

        if (principal instanceof UserDetails) {
            username = ((UserDetails) principal).getUsername();
        } else if (principal instanceof OAuth2User) {
            username = ((OAuth2User) principal).getAttribute("name");
            if (username == null) {
                username = ((OAuth2User) principal).getAttribute("login");
            }
            if (username == null) {
                username = ((OAuth2User) principal).getName();
            }
            //
            // vvv ADD THIS NEW BLOCK vvv
            //
        } else if (principal instanceof Saml2AuthenticatedPrincipal) {
            Saml2AuthenticatedPrincipal samlPrincipal = (Saml2AuthenticatedPrincipal) principal;
            // Get the user's email, which is the NameID
            username = samlPrincipal.getName();
            //
            // ^^^ END OF NEW BLOCK ^^^
            //
        } else if (principal != null) {
            username = principal.toString();
        } else {
            return "redirect:/login";
        }

        model.addAttribute("username", username);
        return "dashboard";
    }



    /**
     * 🚀 NEW: Mapping for the Admin Dashboard.
     * This path is secured in WebSecurityConfig to only allow users with the 'ADMIN' role.
     */
    @GetMapping("/admindashboard")
    public String adminDashboardPage(
            Model model,
            @AuthenticationPrincipal Object principal) { // ⬅️ ADD HttpServletRequest

        String username;

        if (principal instanceof UserDetails) {
            username = ((UserDetails) principal).getUsername();
        } else {
            username = "Admin User";
        }

        // 1. Fetch all users from the database and separate by provider
        java.util.List<User> allUsers = userRepository.findAll();
        java.util.List<User> nativeUsers = allUsers.stream()
                .filter(user -> user.getProvider() == AuthProvider.LOCAL)
                .collect(java.util.stream.Collectors.toList());
        java.util.List<User> ssoUsers = allUsers.stream()
                .filter(user -> user.getProvider() != AuthProvider.LOCAL)
                .collect(java.util.stream.Collectors.toList());

        model.addAttribute("nativeUsers", nativeUsers);
        model.addAttribute("ssoUsers", ssoUsers);
        model.addAttribute("username", username);
        return "admindashboard";
    }
}