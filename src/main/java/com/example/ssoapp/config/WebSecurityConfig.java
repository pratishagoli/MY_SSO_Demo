package com.example.ssoapp.config;

import com.example.ssoapp.security.jwt.JwtAuthenticationFilter;
import com.example.ssoapp.security.jwt.JwtAuthenticationSuccessHandler;
import com.example.ssoapp.security.saml.SamlAuthSuccessHandler;
import com.example.ssoapp.service.CustomOAuth2UserService;
import com.example.ssoapp.service.UserDetailsServiceImpl;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.registration.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final TenantFilter tenantFilter;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler;
    private final SamlAuthSuccessHandler samlAuthSuccessHandler;
    private final UserDetailsServiceImpl userDetailsService;

    // Use @Lazy to break circular dependency
    @Autowired
    public WebSecurityConfig(
            CustomOAuth2UserService customOAuth2UserService,
            TenantFilter tenantFilter,
            JwtAuthenticationFilter jwtAuthenticationFilter,
            JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler,
            SamlAuthSuccessHandler samlAuthSuccessHandler,
            UserDetailsServiceImpl userDetailsService) {
        this.customOAuth2UserService = customOAuth2UserService;
        this.tenantFilter = tenantFilter;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.jwtAuthenticationSuccessHandler = jwtAuthenticationSuccessHandler;
        this.samlAuthSuccessHandler = samlAuthSuccessHandler;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            @Lazy RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
            OpenSaml4AuthenticationProvider samlAuthenticationProvider) throws Exception {

        // Add TenantFilter before the standard authentication filter
        http.addFilterBefore(tenantFilter, UsernamePasswordAuthenticationFilter.class);

        http
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/auth/**", "/api/secret/**"))

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/login", "/signup", "/register-user", "/error").permitAll()
                        // ✅ NEW: Allow public tenant signup
                        .requestMatchers("/tenant-signup", "/api/tenant/signup").permitAll()
                        .requestMatchers("/api/auth/**", "/oauth2/**", "/api/secret/**").permitAll()
                        .requestMatchers("/static/**", "/css/**", "/js/**").permitAll()
                        .requestMatchers("/auth/jwt/callback", "/jwt/callback").permitAll()
                        .requestMatchers("/sso/saml/**").permitAll()
                        .requestMatchers("/login/saml2/**").permitAll()
                        .requestMatchers("/saml2/**").permitAll()

                        // SuperAdmin routes (Updated to match controller @RequestMapping)
                        .requestMatchers("/superadmin/**").hasAuthority("ROLE_SUPERADMIN")

                        // Admin routes
                        .requestMatchers(HttpMethod.PUT, "/api/admin/users/**").hasAnyAuthority("ROLE_TENANT_ADMIN", "ROLE_SUPERADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/admin/users/**").hasAnyAuthority("ROLE_TENANT_ADMIN", "ROLE_SUPERADMIN")
                        // ❌ Removed the old static path '/superadmin-dashboard' as it's now handled by '/superadmin/**'
                        .requestMatchers("/admin/sso/config").hasAnyAuthority("ROLE_TENANT_ADMIN", "ROLE_SUPERADMIN")
                        .requestMatchers("/admin/sso/config/**").hasAnyAuthority("ROLE_TENANT_ADMIN", "ROLE_SUPERADMIN")
                        .requestMatchers("/admin/sso/test/attributes").hasAnyAuthority("ROLE_TENANT_ADMIN", "ROLE_SUPERADMIN")

                        // Public test/callback routes
                        .requestMatchers("/admin/sso/test/jwt/callback").permitAll()
                        .requestMatchers("/admin/sso/test/**").permitAll()

                        .anyRequest().authenticated()
                )

                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .invalidSessionUrl("/login?error=session_expired")
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                )

                // Form login
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(jwtAuthenticationSuccessHandler)
                        .failureUrl("/login?error=true")
                        .permitAll()
                )
                .authenticationProvider(authenticationProvider())
                .authenticationProvider(samlAuthenticationProvider)

                // OAuth2 / OIDC
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .userInfoEndpoint(userInfo -> {
                            userInfo.userService(customOAuth2UserService);
                            userInfo.oidcUserService(oidcUserService());
                        })
                        .successHandler((request, response, authentication) -> {
                            Boolean testMode = (Boolean) request.getSession().getAttribute("sso_test_mode");
                            String testType = (String) request.getSession().getAttribute("sso_test_type");
                            if (Boolean.TRUE.equals(testMode) && "OIDC".equals(testType)) {
                                java.util.Map<String, Object> testResult = new java.util.HashMap<>();
                                testResult.put("testType", "OIDC");
                                testResult.put("testStatus", "success");

                                if (authentication.getPrincipal() instanceof org.springframework.security.oauth2.core.user.OAuth2User) {
                                    org.springframework.security.oauth2.core.user.OAuth2User oauth2User =
                                            (org.springframework.security.oauth2.core.user.OAuth2User) authentication.getPrincipal();
                                    testResult.put("attributes", oauth2User.getAttributes());
                                }

                                request.getSession().setAttribute("sso_test_result", testResult);
                                request.getSession().removeAttribute("sso_test_mode");
                                request.getSession().removeAttribute("sso_test_type");

                                restoreAdminSessionForTest(request, authentication);
                                response.sendRedirect("/admin/sso/config?test=success");
                            } else {
                                response.sendRedirect("/dashboard");
                            }
                        })
                )

                // SAML2 login
                .saml2Login(saml2 -> saml2
                        .loginPage("/login")
                        .relyingPartyRegistrationRepository(relyingPartyRegistrationRepository)
                        .successHandler((request, response, authentication) -> {
                            org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger("SAML2Login");
                            logger.info("=== SAML2 LOGIN SUCCESS HANDLER INVOKED ===");
                            logger.info("Request URI: {}", request.getRequestURI());
                            logger.info("Principal type: {}", authentication.getPrincipal().getClass().getName());
                            samlAuthSuccessHandler.onAuthenticationSuccess(request, response, authentication);
                        })
                        .failureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error=saml_failed") {
                            @Override
                            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger("SAML2Failure");
                                logger.error("!!!!!!!!!!!!!!!!! SAML AUTHENTICATION FAILED !!!!!!!!!!!!!!!!!");
                                logger.error("Failure Message: {}", exception.getMessage());
                                logger.error("Exception Cause: ", exception.getCause());
                                logger.error("Full Exception: ", exception);
                                logger.error("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                                super.onAuthenticationFailure(request, response, exception);
                            }
                        })
                        .defaultSuccessUrl("/dashboard", true)
                )

                // Logout
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID", "AUTH_TOKEN")
                )

                // Exception handling
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.sendRedirect("/login?error=session_expired");
                        })
                );

        // Add JWT filter
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public OAuth2UserService<org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest, OidcUser> oidcUserService() {
        final OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            OidcUser oidcUser = delegate.loadUser(userRequest);
            customOAuth2UserService.loadUser(userRequest);
            return oidcUser;
        };
    }

    @Bean
    public OpenSaml4AuthenticationProvider samlAuthenticationProvider() {
        OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();

        provider.setResponseAuthenticationConverter(responseToken -> {
            org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger("SAMLResponseConverter");
            logger.info("=== PROCESSING SAML RESPONSE ===");
            logger.info("Response ID: {}", responseToken.getResponse().getID());
            logger.info("InResponseTo: {}", responseToken.getResponse().getInResponseTo());
            logger.info("Destination: {}", responseToken.getResponse().getDestination());

            try {
                var authResult = OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter()
                        .convert(responseToken);

                logger.info("SAML response converted successfully");
                logger.info("Principal: {}", authResult.getPrincipal());
                logger.info("Authorities: {}", authResult.getAuthorities());

                return authResult;
            } catch (Exception e) {
                logger.error("CRITICAL: Failed to convert SAML response", e);
                throw e;
            }
        });

        return provider;
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    private void restoreAdminSessionForTest(jakarta.servlet.http.HttpServletRequest request, org.springframework.security.core.Authentication testAuth) {
        org.springframework.security.core.Authentication adminAuth =
                (org.springframework.security.core.Authentication) request.getSession().getAttribute("admin_test_principal");
        if (adminAuth != null) {
            org.springframework.security.core.context.SecurityContext securityContext =
                    org.springframework.security.core.context.SecurityContextHolder.getContext();
            securityContext.setAuthentication(adminAuth);

            jakarta.servlet.http.HttpSession session = request.getSession();
            session.setAttribute(
                    org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                    securityContext
            );

            request.getSession().removeAttribute("admin_test_principal");
            request.getSession().removeAttribute("admin_test_authorities");
        }
    }
}