package com.vanessa.system.auth.dtos;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record InitiatePasswordResetDTO(
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid.")
        String email
) {
}
//validation of the user input when resting the password on a form