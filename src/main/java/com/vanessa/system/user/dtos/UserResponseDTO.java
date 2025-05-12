package com.vanessa.system.user.dtos;

import java.util.UUID;

public record UserResponseDTO(
        UUID id,
        String firstName,
        String lastName,
        String email
) {
}

