// This file defines a REST controller that handles authentication-related endpoints like registration, login, account verification, and password reset.

package com.vanessa.system.auth;

// Import necessary classes including DTOs for request/response, email service, exceptions, etc.
import com.vanessa.system.auth.dtos.*;
import com.vanessa.system.email.EmailService;
import com.vanessa.system.commons.exceptions.BadRequestException;
import com.vanessa.system.user.UserService;
import com.vanessa.system.user.dtos.UserResponseDTO;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

// Annotates this class as a REST controller, which makes it handle web requests and produce JSON responses
@RestController

// Lombok annotation to generate a constructor for all final fields (dependencies)
@AllArgsConstructor

// Base URL path for all endpoints in this controller
@RequestMapping("/auth")
public class AuthController {

    // Inject services used in the authentication process
    private final AuthService authService;
    private final UserService userService;
    private final OtpService otpService;
    private final EmailService emailService;

    // Endpoint to handle user registration
    @PostMapping("/register")
    // Protects the endpoint from being called too frequently (rate limiting)
    @RateLimiter(name = "auth-rate-limiter")
    public ResponseEntity<UserResponseDTO> registerUser(@Valid @RequestBody
                                                        RegisterRequestDTO user, UriComponentsBuilder uriBuilder){

        // Register a new user using the user service
        var userResponse = userService.createUser(user);

        // Build the URI for the created user to include in the response header
        var uri = uriBuilder.path("/users/{id}").buildAndExpand(userResponse.id()).toUri();

        // Generate a verification OTP to be sent to the user's email
        var otpToSend = otpService.generateOtp(userResponse.email(), OtpType.VERIFY_ACCOUNT);

        // Send the verification OTP via email
        emailService.sendAccountVerificationEmail(userResponse.email(), userResponse.firstName(), otpToSend);

        // Return a "201 Created" response with the user data and location URI
        return ResponseEntity.created(uri).body(userResponse);
    }

    // Endpoint to verify a user's account using an OTP
    @PatchMapping("/verify-account")
    @RateLimiter(name = "auth-rate-limiter")
    ResponseEntity<?> verifyAccount(@Valid @RequestBody VerifyAccountDto verifyAccountRequest){

        // Verify the OTP for account verification
        if(!otpService.verifyOtp(verifyAccountRequest.email(), verifyAccountRequest.otp(), OtpType.VERIFY_ACCOUNT))
            throw new BadRequestException("Invalid email or OTP");

        // If successful, activate the user's account
        userService.activateUserAccount(verifyAccountRequest.email());

        // Return a success message
        return ResponseEntity.ok("Account Activated successfully");
    }

    // Endpoint to handle user login
    @PostMapping("/login")
    @RateLimiter(name = "auth-rate-limiter")
    public ResponseEntity<LoginResponseDTO> login(@Valid @RequestBody LoginRequestDTO loginRequestDto, HttpServletResponse response) {

        // Authenticate the user and generate tokens
        var loginResult = authService.login(loginRequestDto, response);

        // Return the access token in the response
        return ResponseEntity.ok(new LoginResponseDTO(loginResult.accessToken()));
    }

    // Endpoint to initiate a password reset by sending an OTP to the user's email
    @PostMapping("/initiate-password-reset")
    ResponseEntity<?> initiatePasswordReset(@Valid @RequestBody InitiatePasswordResetDTO initiateRequest){

        // Generate a reset password OTP
        var otpToSend = otpService.generateOtp(initiateRequest.email(), OtpType.RESET_PASSWORD);

        // Find the user in the system by email
        var user = userService.findByEmail(initiateRequest.email());

        // Send the reset OTP to the user's email
        emailService.sendResetPasswordOtp(user.getEmail(), user.getFirstName(), otpToSend);

        // Return a generic response to avoid email enumeration attacks
        return ResponseEntity.ok("If your email is registered, you will receive an email with instructions to reset your password.");
    }

    // Endpoint to reset the user's password using a valid OTP
    @PatchMapping("/reset-password")
    @RateLimiter(name = "auth-rate-limiter")
    ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordDto resetPasswordRequest){

        // Verify the OTP
        if(!otpService.verifyOtp(resetPasswordRequest.email(), resetPasswordRequest.otp(), OtpType.RESET_PASSWORD))
            throw new BadRequestException("Invalid email or OTP");

        // Update the user's password if the OTP is valid
        userService.changeUserPassword(resetPasswordRequest.email(), resetPasswordRequest.newPassword());

        // Return a success message
        return ResponseEntity.ok("Password reset went successfully you can login with your new password.");
    }
}

//The file you've shared is the AuthService class, which contains business logic for authentication. This is different from the AuthController class (the one you shared earlier), which simply handles HTTP requests
// and delegates the actual work to services like this on