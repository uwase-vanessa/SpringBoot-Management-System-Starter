package com.vanessa.system.user;

// Importing the DTO for user registration requests
import com.vanessa.system.auth.dtos.RegisterRequestDTO;

// Custom exception to be thrown in case of a bad request
import com.vanessa.system.commons.exceptions.BadRequestException;

// DTO for formatting the response data when returning user info
import com.vanessa.system.user.dtos.UserResponseDTO;

// Mapper interface for converting between DTOs and User entity
import com.vanessa.system.user.mappers.UserMapper;

// Lombok annotation to generate a constructor with all fields
import lombok.AllArgsConstructor;

// Lombok annotation to enable logging (Slf4j)
import lombok.extern.slf4j.Slf4j;

// Marks the class as a Spring service component (bean)
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service // This tells Spring to manage this class as a service component
@AllArgsConstructor // Lombok will generate a constructor injecting all final fields
@Slf4j // Enables the use of the log object to log messages
public class UserService {

    // Repository for accessing and managing User data in the database
    private final UserRepository userRepository;

    // Mapper for converting between RegisterRequestDTO ↔ User ↔ UserResponseDTO
    private final UserMapper userMapper;

    // Password encoder for encrypting user passwords
    private final PasswordEncoder passwordEncoder;

    // Method to create and save a new user from the registration DTO
    public UserResponseDTO createUser(RegisterRequestDTO user){

        // Check if a user already exists with the given email, national ID, or phone number
        if(userRepository.existsByEmailOrPhoneNumberOrNationalId(user.email(), user.nationalId(),user.phoneNumber())){
            // If yes, throw an exception to prevent duplication
            throw new BadRequestException("User with this email or nationalId or phoneNumber already exists");
        }

        // Convert the RegisterRequestDTO to a User entity using the mapper
        var newUser = userMapper.toEntity(user);

        // Encrypt and set the password
        newUser.setPassword(passwordEncoder.encode(user.password()));

        // Set the default role to USER
        newUser.setRole(Role.ADMIN);

        // Disable the user account until activated manually
        newUser.setEnabled(false);

        // Log the creation of the user
        log.info("User created: {}", newUser);

        // Save the new user to the database
        userRepository.save(newUser);

        // Convert and return the saved user as a response DTO
        return userMapper.toResponseDTO(newUser);
    }

    // Method to update a user's password using their email
    public void changeUserPassword(String userEmail, String newPassword){
        // Find the user by email or throw an exception if not found
        var user = findByEmail(userEmail);

        // Encrypt and update the user's password
        user.setPassword(passwordEncoder.encode(newPassword));

        // Save the updated user back to the database
        userRepository.save(user);
    }

    // Method to activate a user's account using their email
    public void activateUserAccount(String userEmail){
        // Find the user by email
        var user = findByEmail(userEmail);

        // Set the account to enabled
        user.setEnabled(true);

        // Save the change to the database
        userRepository.save(user);
    }

    // Helper method to find a user by email or throw an exception if not found
    public User findByEmail(String email){
        // Return the user if found, otherwise throw BadRequestException
        return userRepository.findByEmail(email).orElseThrow(() -> new BadRequestException("User with that email not found."));
    }
}
