package com.vanessa.system.user.mappers;

import com.vanessa.system.auth.dtos.RegisterRequestDTO;
import com.vanessa.system.user.User;
import org.mapstruct.Builder;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import com.vanessa.system.user.dtos.UserResponseDTO;

@Mapper(componentModel = "spring", builder = @Builder(disableBuilder = true))
public interface    UserMapper {

    @Mapping(target = "role", ignore = true)
    @Mapping(target = "enabled", ignore = true)
    User toEntity(RegisterRequestDTO userDto);
    UserResponseDTO toResponseDTO(User user);
}
//simplifying data transformation in the user registration and response process.