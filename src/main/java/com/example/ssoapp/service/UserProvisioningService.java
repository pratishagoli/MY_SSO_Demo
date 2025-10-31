//package com.example.ssoapp.service;
//
//import com.example.ssoapp.model.AuthProvider;
//import com.example.ssoapp.model.User;
//import com.example.ssoapp.repository.UserRepository;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.dao.DataIntegrityViolationException;
//import org.springframework.stereotype.Service;
//import org.springframework.transaction.annotation.Propagation;
//import org.springframework.transaction.annotation.Transactional;
//
//import java.util.Optional;
//
//@Service
//public class UserProvisioningService {
//
//    private static final Logger logger = LoggerFactory.getLogger(UserProvisioningService.class);
//
//    @Autowired
//    private UserRepository userRepository;
//
//    @Transactional(propagation = Propagation.REQUIRES_NEW)
//    public User createUserIfNotExists(String email, String username, String providerId, AuthProvider provider) {
//        logger.info("Provisioning new user: email={}, username={}, providerId={}, provider={}",
//                email, username, providerId, provider);
//        Optional<User> existingUser = userRepository.findByEmail(email);
//        if (existingUser.isPresent()) return existingUser.get();
//
//        User newUser = new User();
//        newUser.setEmail(email);
//        newUser.setUsername(username);
//        newUser.setProviderId(providerId);
//        newUser.setProvider(provider);
//        newUser.setPassword("");
//
//        try {
//            User savedUser = userRepository.save(newUser);
//            userRepository.flush();
//            logger.info("User saved: id={}, email={}", savedUser.getId(), savedUser.getEmail());
//            return savedUser;
//        } catch (DataIntegrityViolationException e) {
//            logger.error("Database constraint violation while saving user: {}", email, e);
//            throw e;
//        }
//    }
//
//    @Transactional(readOnly = true)
//    public Optional<User> findUserByEmail(String email) {
//        return userRepository.findByEmail(email);
//    }
//}
