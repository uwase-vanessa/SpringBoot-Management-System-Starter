package com.vanessa.system.auth;

import com.vanessa.system.auth.exceptions.InvalidJwtException;
import com.vanessa.system.user.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@AllArgsConstructor
@Slf4j
public class JwtService {

    private final JwtConfig config;

    /**
     * Generates a JWT Access Token with short expiration (e.g., 15 minutes).
     */
    Jwt generateAccessToken(User user) {
        return generateToken(user, config.getAccessTokenExpiration());
    }

    /**
     * Generates a JWT Refresh Token with long expiration (e.g., 7 days).
     */
    Jwt generateRefreshToken(User user) {
        return generateToken(user, config.getRefreshTokenExpiration());
    }

    /**
     * Generates a token (access or refresh) with claims like user ID, email, phone number, and role.
     */
    private Jwt generateToken(User user, long tokenExpiration) {
        var claims = Jwts.claims()
                .subject(user.getId().toString())
                .add("email", user.getEmail())
                .add("phoneNumber", user.getPhoneNumber())
                .add("role", user.getRole())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000 * tokenExpiration))
                .build();

        return new Jwt(claims, config.getSecretKey());
    }

    /**
     * Parses and verifies a JWT token string, throws exception if invalid or expired.
     */
    Jwt parseToken(String token) {
        try {
            var claims = getClaims(token);
            return new Jwt(claims, config.getSecretKey());
        } catch (ExpiredJwtException ex) {
            log.debug("Token expired: {}", ex.getMessage());
            throw new InvalidJwtException("Token expired");
        } catch (SignatureException ex) {
            log.debug("Invalid token signature: {}", ex.getMessage());
            throw new InvalidJwtException("Invalid token signature");
        } catch (JwtException | IllegalArgumentException ex) {
            log.debug("Invalid token: {}", ex.getMessage());
            throw new InvalidJwtException("Invalid token");
        }
    }

    /**
     * Internal method that extracts the Claims from a signed JWT.
     * The annotation @AllArgsConstructor is from Lombok, and it automatically creates a constructor that
     * initializes all final fields or all fields if none are final.
     */
    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(config.getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
