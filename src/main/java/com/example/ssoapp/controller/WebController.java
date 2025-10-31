package com.example.ssoapp.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WebController {

    @GetMapping("/login")
    public String loginPage() {
        return "login"; // Renders src/main/resources/templates/login.html
    }

    // --- ADD THIS NEW METHOD ---
    @GetMapping("/signup")
    public String signupPage() {
        return "signup"; // Renders src/main/resources/templates/signup.html
    }
    // ---------------------------

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
        } else if (principal != null) {
            username = principal.toString();
        } else {
            return "redirect:/login"; // Redirect to login if principal is null
        }

        model.addAttribute("username", username);
        return "dashboard";
    }
}