//package com.example.ssoapp.security.jwt;
//
//import jakarta.servlet.http.Cookie;
//import jakarta.servlet.http.HttpServletRequest;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.http.ResponseCookie; // <-- Import this
//import org.springframework.stereotype.Component;
//import org.springframework.web.util.WebUtils;
//
//@Component
//public class JwtCookieUtils {
//
//    @Value("${app.jwt.cookieName:jwtToken}")
//    private String jwtCookieName;
//
//    @Value("${app.jwt.expiration-ms}")
//    private int jwtExpirationMs;
//
//    // This method for reading the cookie is fine, no changes needed
//    public Cookie getJwtCookie(HttpServletRequest request) {
//        return WebUtils.getCookie(request, jwtCookieName);
//    }
//
//    // --- UPDATED METHOD ---
//    // We now return a ResponseCookie object
//    public ResponseCookie createJwtCookie(String jwt) {
//        return ResponseCookie.from(jwtCookieName, jwt)
//                .path("/")
//                .maxAge(jwtExpirationMs / 1000)
//                .httpOnly(true)
//                .sameSite("Lax") // <-- This is the key fix
//                // .secure(true) // Uncomment this for production (HTTPS)
//                .build();
//    }
//
//    // --- UPDATED METHOD ---
//    // Create a "clear" cookie
//    public ResponseCookie createClearJwtCookie() {
//        return ResponseCookie.from(jwtCookieName, null)
//                .path("/")
//                .maxAge(0) // Expires the cookie immediately
//                .httpOnly(true)
//                .sameSite("Lax")
//                // .secure(true)
//                .build();
//    }
//}