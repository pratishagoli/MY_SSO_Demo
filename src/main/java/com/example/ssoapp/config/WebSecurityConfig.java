package com.example.ssoapp.config;

import com.example.ssoapp.security.UserDetailsServiceImpl;
import com.example.ssoapp.service.CustomOAuth2UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        System.out.println("\n==========================================");
        System.out.println(">>> SECURITY CONFIG LOADED");
        System.out.println(">>> CustomOAuth2UserService: " + customOAuth2UserService);
        System.out.println("==========================================\n");

        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/login", "/signup", "/error").permitAll()
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/oauth2/**").permitAll()
                        .requestMatchers("/static/**", "/css/**", "/js/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/dashboard", true)
                        .permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .userInfoEndpoint(userInfo -> {
                            // CRITICAL FIX: Set BOTH OAuth2UserService AND OidcUserService
                            userInfo.userService(customOAuth2UserService);
                            userInfo.oidcUserService(oidcUserService());
                        })
                        .defaultSuccessUrl("/dashboard", true)
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, authException) ->
                                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized")
                        )
                );

        return http.build();
    }

    /**
     * CRITICAL: MiniOrange uses OIDC (OpenID Connect), not plain OAuth2.
     * We need to configure an OidcUserService that delegates to our custom service.
     */
    @Bean
    public OAuth2UserService<org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest, OidcUser> oidcUserService() {
        final OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            // First, load the user using the default OIDC service
            OidcUser oidcUser = delegate.loadUser(userRequest);

            System.out.println("\n==========================================");
            System.out.println(">>> OIDC USER SERVICE CALLED <<<");
            System.out.println(">>> Delegating to CustomOAuth2UserService");
            System.out.println("==========================================\n");

            // Now delegate to our custom service for user registration
            // We call loadUser which will trigger our custom logic
            customOAuth2UserService.loadUser(userRequest);

            // Return the OIDC user for Spring Security to use
            return oidcUser;
        };
    }
}
