package com.vanessa.system.auth.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;


public record LoginRequestDTO(
        @NotBlank(message = "Field is required")
        @Email(message = "Email must be valid.")
        String email,

        @NotBlank(message = "Password is required")
        String password

) {
}
