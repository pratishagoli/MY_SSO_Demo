package com.example.ssoapp.config;

import com.example.ssoapp.config.HibernateTenantFilterConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration to register the Hibernate listener that enables/disables the tenant filter.
 */
@Configuration
public class JpaConfig {

    @Bean
    public HibernateTenantFilterConfigurer hibernateTenantFilterConfigurer() {
        return new HibernateTenantFilterConfigurer();
    }
}