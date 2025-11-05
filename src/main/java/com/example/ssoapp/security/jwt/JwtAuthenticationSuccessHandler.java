package com.example.ssoapp.security.jwt;

import com.example.ssoapp.service.JwtValidationService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationSuccessHandler.class);

    @Autowired
    private JwtValidationService jwtValidationService;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        logger.info("Form login successful. Generating JWT for user: {}", authentication.getName());

        String jwtToken = null;
        Object principal = authentication.getPrincipal();
        String targetUrl = "/dashboard"; // Default redirect URL

        if (principal instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) principal;
            String username = userDetails.getUsername();

            // 1. **ROLE CHECK & REDIRECT LOGIC** ⬅️ NEW
            // Get the user's roles/authorities
            String roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(","));

            // Check for the ADMIN role (assuming the role is 'ADMIN' based on your image)
            if (roles.contains("ADMIN")) {
                targetUrl = "/admindashboard"; // Redirect to admin path
                logger.info("User {} is ADMIN, redirecting to: {}", username, targetUrl);
            } else {
                targetUrl = "/dashboard"; // Redirect to general user dashboard path
                logger.info("User {} is USER, redirecting to: {}", username, targetUrl);
            }
            // ------------------------------------

            // 2. Generate the JWT (Implementation is in JwtValidationService)
            jwtToken = jwtValidationService.generateToken(username, roles); // Pass roles to generate token
            Cookie jwtCookie = new Cookie("AUTH_TOKEN", jwtToken);
        }

        if (jwtToken != null) {
            // 3. Add the JWT to the HTTP response as a secure, HttpOnly cookie
            Cookie jwtCookie = new Cookie("AUTH_TOKEN", jwtToken);
            jwtCookie.setPath("/");
            jwtCookie.setHttpOnly(true);
            jwtCookie.setMaxAge(7 * 24 * 60 * 60);
            response.addCookie(jwtCookie);
        } else {
            logger.warn("JWT generation failed for user: {}", authentication.getName());
        }

        // 4. Redirect the user to the determined dashboard
        response.sendRedirect(targetUrl); // ⬅️ USED TARGET URL
    }
}