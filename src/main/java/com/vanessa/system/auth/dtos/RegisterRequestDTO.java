package com.vanessa.system.auth.dtos;

import com.vanessa.system.commons.validation.ValidRwandaId;
import com.vanessa.system.commons.validation.ValidRwandanPhoneNumber;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequestDTO(
        @NotBlank(message = "First name is required")
        @Size(min = 3, max = 50, message = "First name must be between 2 and 50 characters long")
        String firstName,

        @NotBlank(message = "Last name is required")
        String lastName,

        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid.")
        String email,

        @NotBlank(message = "Phone number is required.")
        @ValidRwandanPhoneNumber
        String phoneNumber,

        @NotBlank(message = "National ID is required.")
        @ValidRwandaId
        String nationalId,

        @NotBlank(message = "Password is required")
        @Size(min = 8, max = 250, message = "Password must be at least 8 characters long")
        String password
) {
}