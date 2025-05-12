package com.vanessa.system.auth;

import com.vanessa.system.user.Role; // Your custom enum representing user roles
import io.jsonwebtoken.Claims; // A map-like object that holds all token data
import io.jsonwebtoken.Jwts; // Utility class for creating JWT tokens
import lombok.RequiredArgsConstructor; // Lombok annotation to generate a constructor for final fields

import javax.crypto.SecretKey; // The secret key used to sign JWTs
import java.util.Date;
import java.util.UUID;

@RequiredArgsConstructor // Generates constructor: Jwt(Claims claims, SecretKey secretKey)
    public class Jwt {
    private final Claims claims;       // Holds all the decoded data from the JWT token
    private final SecretKey secretKey; // Secret used to sign (or re-sign) the JWT

    public boolean isExpired(){
        return claims.getExpiration().before(new Date());
    }

    public UUID getUserId(){
        return UUID.fromString(claims.getSubject());
    }
    // Get role from token
    public Role getRole() {
        return Role.valueOf(claims.get("role", String.class));
    }
    // Convert claims back to token string
    public String toString(){
        return Jwts.builder().claims(claims).signWith(secretKey).compact();
    }
}
