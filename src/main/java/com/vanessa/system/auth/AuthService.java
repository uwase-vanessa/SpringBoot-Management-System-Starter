package com.vanessa.system.auth;

import com.vanessa.system.auth.dtos.LoginRequestDTO;
import com.vanessa.system.auth.dtos.LoginResponseDTO;
import com.vanessa.system.user.User;
import com.vanessa.system.user.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@AllArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    public User getCurrentUser(){
        var authentication = SecurityContextHolder.getContext().getAuthentication();

        var userId = (UUID) authentication.getPrincipal();

        return userRepository.findById(userId).orElse(null);
    }

    public LoginResponseDTO login(LoginRequestDTO loginRequest, HttpServletResponse response){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.email(),
                        loginRequest.password()
                )
        );

        var user =  userRepository.findByEmail(loginRequest.email()).orElseThrow();

        var accessToken = jwtService.generateAccessToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        var cookie = new Cookie("refreshToken", refreshToken.toString());
        cookie.setHttpOnly(true);
        cookie.setPath("/auth/refresh");
        cookie.setMaxAge(60 * 60 * 24 * 7); // 30 days
        cookie.setSecure(true);
        response.addCookie(cookie);

        return new LoginResponseDTO(
                accessToken.toString()
        );
    }
    public String refreshAccessToken(String refreshToken){
        var jwt = jwtService.parseToken(refreshToken);
        if (jwt == null || jwt.isExpired()) {
            throw new BadCredentialsException("Refresh token is missing.");
        }
        var user = userRepository.findById(jwt.getUserId()).orElseThrow();
        return jwtService.generateAccessToken(user).toString();
    }

}

//Purpose: Allows the user to get a new access token without re-entering credentials by using a valid refresh token
//AuthenticationManager: A Spring Security class that checks user credentials.
////
//UserRepository: Custom interface for accessing user data from the database.
//
//JwtService: A custom service that handles JWT token creation and validation.