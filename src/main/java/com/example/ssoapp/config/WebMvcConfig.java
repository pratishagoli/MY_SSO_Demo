// File: com.example.ssoapp.config.WebMvcConfig.java

package com.example.ssoapp.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.security.web.csrf.CsrfToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry; // 👈 Don't forget this import

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new CsrfTokenInterceptor());
    }

    private static class CsrfTokenInterceptor implements HandlerInterceptor {
        @Override
        public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
            // Check if a view is being rendered and if the model is available
            if (modelAndView != null && modelAndView.hasView()) {
                // Retrieve the CsrfToken object put on the request by Spring Security
                CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

                if (token != null) {
                    // Inject the token object into the Thymeleaf Model under the attribute name '_csrf'
                    modelAndView.addObject("_csrf", token);
                }
            }
        }
    }
}