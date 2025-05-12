package com.vanessa.system.user;

// Lombok annotation to generate a constructor with all class fields
import lombok.AllArgsConstructor;

// Spring Security classes for user authentication
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

// Spring annotation to mark this class as a service component
import org.springframework.stereotype.Service;

import java.util.Collections; // Used to return an empty list of authorities (roles)

// Marks this class as a Spring-managed service (bean)
@Service

// Generates a constructor that takes all required dependencies (here, UserRepository)
@AllArgsConstructor
public class CustomeUserDetailsService implements UserDetailsService {

    // Repository to fetch user information from the database
    private final UserRepository userRepository;

    // Override the method from UserDetailsService to load a user by username (in this case, email)
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        // Attempt to find the user in the database by email
        var user = userRepository.findByEmail(email)
                // If the user is not found, throw a Spring Security exception
                .orElseThrow(() -> new UsernameNotFoundException(email));

        // Return a Spring Security User object with email as username, the hashed password, and an empty list of authorities
        // This object is used by Spring Security during authentication
        return new User(user.getEmail(), user.getPassword(), Collections.emptyList());
    }
}
