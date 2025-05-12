package com.vanessa.system.auth;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@AllArgsConstructor
@Service
@Slf4j
public class OtpService {

    // RedisTemplate is the Spring abstraction to interact with Redis key-value store
    private final RedisTemplate<String, String> redisTemplate;

    // ValueOperations provides Redis GET/SET operations on string keys
    private final ValueOperations<String, String> valueOperations;

    /**
     * Generates a 6-digit OTP, stores it in Redis with a 10-minute TTL, and returns it.
     */
    String generateOtp(String userEmail, OtpType otpType) {
        var otp = generateOtp(); // generates a random 6-digit OTP
        String key = generateKey(userEmail, otp, otpType);
        storeOtp(key, otp); // stores OTP in Redis for 10 minutes
        return otp;
    }

    /**
     * Verifies the provided OTP against what's stored in Redis.
     * If it exists and matches, it's deleted and returns true.
     */
    boolean verifyOtp(String userEmail, String otp, OtpType otpType) {
        String key = generateKey(userEmail, otp, otpType);
        if (hasOtp(key)) {
            String storedOtp = getOtp(key);
            if (storedOtp.equals(otp)) {
                deleteOtp(key);
                return true;
            }
        }
        return false;
    }

    // Reads the OTP from Redis
    private String getOtp(String key) {
        return valueOperations.get(key);
    }

    // Deletes the OTP key from Redis after verification
    private void deleteOtp(String key) {
        redisTemplate.delete(key);
    }

    // Checks if OTP key exists in Redis
    private boolean hasOtp(String key) {
        return redisTemplate.hasKey(key);
    }

    // Formats Redis key as: OTP_TYPE:user@example.com:123456
    private String generateKey(String userEmail, String otp, OtpType otpType) {
        return String.format("%s:%s:%s", otpType.toString(), userEmail, otp);
    }

    // Stores OTP with a 10-minute time-to-live
    private void storeOtp(String key, String otp) {
        valueOperations.set(key, otp, 10, TimeUnit.MINUTES);
        log.info("Storing OTP successfully");
    }

    // Randomly generates a 6-digit OTP
    private String generateOtp() {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            int digit = (int) (Math.random() * 10);
            otp.append(digit);
        }
        return otp.toString();
    }
}
