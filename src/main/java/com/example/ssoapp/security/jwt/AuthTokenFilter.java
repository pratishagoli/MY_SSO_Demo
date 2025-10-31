//package com.example.ssoapp.security.jwt;
//
//import com.example.ssoapp.security.UserDetailsServiceImpl;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.Cookie;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.ResponseCookie;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.util.StringUtils;
//import org.springframework.web.filter.OncePerRequestFilter;
//import org.springframework.stereotype.Component;
//
//import java.io.IOException;
//
//@Component
//public class AuthTokenFilter extends OncePerRequestFilter {
//    @Autowired
//    private JwtUtils jwtUtils;
//    @Autowired
//    private UserDetailsServiceImpl userDetailsService;
//    @Autowired
//    private JwtCookieUtils jwtCookieUtils; // <-- This is required
//
//    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//            throws ServletException, IOException {
//        try {
//            // parseJwt() will now check the URL parameter, cookie, and header
//            String jwt = parseJwt(request);
//
//            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
//                String username = jwtUtils.getUserNameFromJwtToken(jwt);
//
//                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//                UsernamePasswordAuthenticationToken authentication =
//                        new UsernamePasswordAuthenticationToken(userDetails,
//                                null,
//                                userDetails.getAuthorities());
//                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//
//                SecurityContextHolder.getContext().setAuthentication(authentication);
//
//                // --- THIS IS THE KEY FIX ---
//                // If the token came from the URL (meaning a fresh login),
//                // we set the secure HttpOnly cookie for future refreshes.
//                if (StringUtils.hasText(request.getParameter("token"))) {
//                    ResponseCookie cookie = jwtCookieUtils.createJwtCookie(jwt);
//                    response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
//                }
//            }
//        } catch (Exception e) {
//            logger.error("Cannot set user authentication: {}", e);
//        }
//
//        filterChain.doFilter(request, response);
//    }
//
//    /**
//     * This method is now updated to check all three locations for a token,
//     * in the correct order of priority.
//     */
//    private String parseJwt(HttpServletRequest request) {
//        // 1. Try to get token from "token" request parameter (for login redirects)
//        String paramToken = request.getParameter("token");
//        if (StringUtils.hasText(paramToken)) {
//            return paramToken;
//        }
//
//        // 2. If not in URL, try to get token from HttpOnly Cookie (for refreshes)
//        Cookie cookie = jwtCookieUtils.getJwtCookie(request);
//        if (cookie != null) {
//            return cookie.getValue();
//        }
//
//        // 3. (Optional) Try from Authorization header (for APIs/mobile)
//        String headerAuth = request.getHeader("Authorization");
//        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
//            return headerAuth.substring(7);
//        }
//
//        return null; // No token found
//    }
//}