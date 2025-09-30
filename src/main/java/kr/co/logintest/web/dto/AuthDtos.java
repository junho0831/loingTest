package kr.co.logintest.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
public class AuthDtos {
    @Data
    public static class RegisterRequest {
        @Email
        @NotBlank
        private String email;

        @NotBlank
        @Size(min = 8, max = 100)
        private String password;

        @NotBlank
        @Size(min = 1, max = 100)
        private String name;
    }

    @Data
    public static class LoginRequest {
        @Email
        @NotBlank
        private String email;

        @NotBlank
        private String password;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TokenMetaResponse {
        private long expiresIn; // seconds for access token
        private String tokenType;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserResponse {
        private Long id;
        private String email;
        private String name;
        private String[] roles;
    }
}
