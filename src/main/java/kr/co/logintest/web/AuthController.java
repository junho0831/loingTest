package kr.co.logintest.web;

import kr.co.logintest.application.AuthService;
import kr.co.logintest.application.JwtTokenService;
import kr.co.logintest.domain.Role;
import kr.co.logintest.domain.User;
import kr.co.logintest.error.ErrorCode;
import kr.co.logintest.web.dto.AuthDtos;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;
    private final JwtTokenService tokenService;

    public AuthController(AuthService authService, JwtTokenService tokenService) {
        this.authService = authService;
        this.tokenService = tokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Validated @RequestBody AuthDtos.RegisterRequest req) {
        User user = authService.register(req);
        var body = Map.of(
                "id", user.getId(),
                "email", user.getEmail(),
                "name", user.getName()
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(body);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthDtos.TokenResponse> login(@Validated @RequestBody AuthDtos.LoginRequest req) {
        var tokens = authService.login(req);
        String access = (String) tokens.get("access");
        String refresh = (String) tokens.get("refresh");
        long expiresIn = tokenService.parseAccess(access).getBody().getExpiration().getTime() / 1000L - System.currentTimeMillis() / 1000L;
        return ResponseEntity.ok(AuthDtos.TokenResponse.builder()
                .accessToken(access)
                .refreshToken(refresh)
                .expiresIn(expiresIn)
                .build());
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthDtos.TokenResponse> refresh(@Validated @RequestBody AuthDtos.RefreshRequest req) {
        var tokens = authService.refresh(req.getRefreshToken());
        String access = (String) tokens.get("access");
        String refresh = (String) tokens.get("refresh");
        long expiresIn = tokenService.parseAccess(access).getBody().getExpiration().getTime() / 1000L - System.currentTimeMillis() / 1000L;
        return ResponseEntity.ok(AuthDtos.TokenResponse.builder()
                .accessToken(access)
                .refreshToken(refresh)
                .expiresIn(expiresIn)
                .build());
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@Validated @RequestBody AuthDtos.LogoutRequest req) {
        authService.logout(req.getRefreshToken());
        return ResponseEntity.noContent().build();
    }
}
