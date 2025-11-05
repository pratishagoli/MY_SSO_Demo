package com.example.ssoapp.security.jwt;

import com.example.ssoapp.model.AuthProvider;
import com.example.ssoapp.model.User;
import com.example.ssoapp.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Optional;

@Service
public class JwtUserService {

    private static final Logger logger = LoggerFactory.getLogger(JwtUserService.class);

    @Autowired
    private UserRepository userRepository;

    /**
     * Register new user or retrieve existing user
     */
    public User registerOrRetrieveUser(String email, String username, String providerId) {
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

    /**
     * Authenticate the given user in the current session
     */
    public void authenticateUser(User user, HttpServletRequest request) {
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
    }
}
