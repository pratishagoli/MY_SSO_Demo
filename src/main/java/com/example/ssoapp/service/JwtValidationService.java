package com.example.ssoapp.service;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;

/**
 * Service for validating JWT tokens from MiniOrange using RSA public certificate
 */
@Component
public class JwtValidationService {

    private static final Logger logger = LoggerFactory.getLogger(JwtValidationService.class);

    @Value("${app.jwt.miniorange.certificate}")
    private String certificateString;

    @Value("${app.jwt.miniorange.issuer}")
    private String expectedIssuer;

    private PublicKey publicKey;

    /**
     * Parse the certificate and extract the public key
     */
    private PublicKey getPublicKey() {
        if (publicKey != null) {
            return publicKey;
        }

        try {
            // Remove header, footer, and whitespace
            String certContent = certificateString
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");

            byte[] certBytes = Base64.getDecoder().decode(certContent);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(certBytes)
            );

            publicKey = certificate.getPublicKey();
            logger.info("Successfully loaded MiniOrange public key");
            return publicKey;

        } catch (Exception e) {
            logger.error("Failed to parse certificate", e);
            throw new RuntimeException("Failed to load MiniOrange certificate", e);
        }
    }

    /**
     * Validate the JWT token and return claims
     */
    public Map<String, Object> validateToken(String token) {
        try {
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(getPublicKey())
                    .requireIssuer(expectedIssuer)
                    .build()
                    .parseClaimsJws(token);

            Claims claims = jws.getBody();

            logger.info("JWT validated successfully for user: {}", claims.get("username"));

            return Map.of(
                    "sub", claims.getSubject(),
                    "email", claims.get("email", String.class),
                    "username", claims.get("username", String.class)
            );

        } catch (ExpiredJwtException e) {
            logger.error("JWT token expired: {}", e.getMessage());
            throw new RuntimeException("Token expired");
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token unsupported: {}", e.getMessage());
            throw new RuntimeException("Token unsupported");
        } catch (MalformedJwtException e) {
            logger.error("JWT token malformed: {}", e.getMessage());
            throw new RuntimeException("Token malformed");
        } catch (SignatureException e) {
            logger.error("JWT signature validation failed: {}", e.getMessage());
            throw new RuntimeException("Invalid token signature");
        } catch (IllegalArgumentException e) {
            logger.error("JWT token is empty: {}", e.getMessage());
            throw new RuntimeException("Token is empty");
        }
    }

    /**
     * Extract token from Authorization header
     */
    public String extractTokenFromHeader(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    public String validateAndExtractEmail(String token) {
        try {
            Map<String, Object> claims = validateToken(token);
            return (String) claims.getOrDefault("email", claims.get("sub"));
        } catch (Exception e) {
            System.err.println("❌ JWT validation failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Basic check for validity.
     */
    public boolean isTokenValid(String token, org.springframework.security.core.userdetails.UserDetails userDetails) {
        String email = validateAndExtractEmail(token);
        return email != null && email.equals(userDetails.getUsername());
    }
    public String generateToken(String username, String roles) {
        // ⚠️ TODO: Update your actual JWT creation logic here!
        // Make sure to add the 'roles' to the claims (e.g., claims.put("role", roles))
        // when building the token.

        // Placeholder update:
        System.out.println("GENERATING TOKEN FOR: " + username + " with roles: " + roles);
        return "a_new_jwt_for_" + username + "_and_role_" + roles.replace(",", "_");
    }
}