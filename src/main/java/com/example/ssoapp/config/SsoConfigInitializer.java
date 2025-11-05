package com.example.ssoapp.config;

import com.example.ssoapp.service.SsoConfigService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class SsoConfigInitializer implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(SsoConfigInitializer.class);

    @Autowired
    private SsoConfigService ssoConfigService;

    @Override
    public void run(String... args) throws Exception {
        logger.info("Initializing default SSO configurations...");
        ssoConfigService.initializeDefaultConfigs();
        logger.info("SSO configurations initialized successfully.");
    }
}

