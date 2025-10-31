package com.example.ssoapp.service;

import com.example.ssoapp.model.AuthProvider;
import com.example.ssoapp.model.User;
import com.example.ssoapp.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private static final Logger logger = LoggerFactory.getLogger(CustomOAuth2UserService.class);

    @Autowired
    private UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        System.out.println("\n==========================================");
        System.out.println(">>> CUSTOM OAUTH2 USER SERVICE CALLED <<<");
        System.out.println("==========================================\n");

        logger.info("SSO LOGIN ATTEMPT - Processing OAuth2 user");

        OAuth2User oAuth2User = super.loadUser(userRequest);
        Map<String, Object> attributes = oAuth2User.getAttributes();

        logger.info("Attributes from MiniOrange:");
        attributes.forEach((key, value) -> logger.info("  {} = {}", key, value));

        String email = (String) attributes.get("email");
        String sub = (String) attributes.get("sub");
        String name = extractName(attributes);

        logger.info("Extracted - Email: {}, Name: {}, Sub: {}", email, name, sub);

        if (email == null || email.trim().isEmpty()) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("missing_email", "Email required", null));
        }

        if (sub == null || sub.trim().isEmpty()) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("missing_sub", "Sub required", null));
        }

        try {
            registerUser(email, name, sub);
        } catch (Exception e) {
            logger.error("User registration failed", e);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("registration_failed", e.getMessage(), null), e);
        }

        logger.info("SSO processing completed\n");
        return oAuth2User;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void registerUser(String email, String name, String providerId) {
        logger.info("Checking if user exists: {}", email);

        Optional<User> existingUser = userRepository.findByEmail(email);

        if (existingUser.isPresent()) {
            logger.info("User already exists - ID: {}", existingUser.get().getId());
            return;
        }

        logger.info("NEW USER - Creating in database...");

        User newUser = new User();
        newUser.setEmail(email);
        newUser.setUsername(name);
        newUser.setProviderId(providerId);
        newUser.setProvider(AuthProvider.MINIORANGE);
        newUser.setPassword(null);

        try {
            User saved = userRepository.saveAndFlush(newUser);
            logger.info("SUCCESS - User saved with ID: {}", saved.getId());
        } catch (Exception e) {
            logger.error("FAILED to save user!", e);
            throw e;
        }
    }

    private String extractName(Map<String, Object> attributes) {
        String[] keys = {"name", "username", "preferred_username", "given_name"};
        for (String key : keys) {
            Object value = attributes.get(key);
            if (value != null && !value.toString().trim().isEmpty()) {
                return value.toString().trim();
            }
        }
        String email = (String) attributes.get("email");
        return email != null ? email.split("@")[0] : "Unknown";
    }
}
