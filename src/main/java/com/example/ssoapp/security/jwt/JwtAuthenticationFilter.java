package com.example.ssoapp.security.jwt;

import com.example.ssoapp.model.AuthProvider;
import com.example.ssoapp.model.User;
import com.example.ssoapp.repository.UserRepository;
import com.example.ssoapp.service.JwtValidationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;

/**
 * Filter to intercept requests and validate JWT tokens from Authorization header
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Autowired
    private JwtValidationService jwtValidationService;

    @Autowired
    private UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {
            String authHeader = request.getHeader("Authorization");
            String jwt = jwtValidationService.extractTokenFromHeader(authHeader);

            if (jwt != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                logger.info("Processing JWT token from Authorization header");

                // Validate token and extract claims
                Map<String, Object> claims = jwtValidationService.validateToken(jwt);

                String email = (String) claims.get("email");
                String username = (String) claims.get("username");
                String sub = (String) claims.get("sub");

                // Register or retrieve user
                User user = registerOrRetrieveUser(email, username, sub);

                // Create authentication
                UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                        user.getUsername(),
                        "",
                        new ArrayList<>()
                );

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);

                logger.info("JWT authentication successful for user: {}", username);
            }

        } catch (Exception e) {
            logger.error("JWT authentication failed: {}", e.getMessage());
            // Don't block the request, just log the error
            // Other auth mechanisms might still work
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Register new user or retrieve existing user
     */
    private User registerOrRetrieveUser(String email, String username, String providerId) {
        Optional<User> existingUser = userRepository.findByEmail(email);

        if (existingUser.isPresent()) {
            logger.info("User already exists: {}", email);
            return existingUser.get();
        }

        logger.info("Creating new user from JWT: {}", email);

        User newUser = new User();
        newUser.setEmail(email);
        newUser.setUsername(username);
        newUser.setProviderId(providerId);
        newUser.setProvider(AuthProvider.MINIORANGE);
        newUser.setPassword(null);

        return userRepository.saveAndFlush(newUser);
    }
}