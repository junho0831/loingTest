package kr.co.logintest.web;

import kr.co.logintest.application.AuthService;
import kr.co.logintest.application.AuthTokens;
import kr.co.logintest.application.JwtTokenService;
import kr.co.logintest.domain.User;
import kr.co.logintest.error.ApiException;
import kr.co.logintest.error.ErrorCode;
import kr.co.logintest.web.dto.AuthDtos;
import kr.co.logintest.web.support.TokenCookieFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final AuthService authService;
    private final JwtTokenService tokenService;
    private final TokenCookieFactory cookieFactory;

    public AuthController(AuthService authService, JwtTokenService tokenService, TokenCookieFactory cookieFactory) {
        this.authService = authService;
        this.tokenService = tokenService;
        this.cookieFactory = cookieFactory;
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
    public ResponseEntity<AuthDtos.TokenMetaResponse> login(@Validated @RequestBody AuthDtos.LoginRequest req) {
        AuthTokens tokens = authService.login(req);
        long expiresIn = computeExpiresIn(tokens.accessToken());
        var accessCookie = cookieFactory.issueAccess(tokens.accessToken());
        var refreshCookie = cookieFactory.issueRefresh(tokens.refreshToken());
        AuthDtos.TokenMetaResponse body = AuthDtos.TokenMetaResponse.builder()
                .expiresIn(expiresIn)
                .tokenType("Bearer")
                .build();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(body);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthDtos.TokenMetaResponse> refresh(@CookieValue(name = "refresh_token", required = false) String refreshToken) {
        AuthTokens tokens = authService.refresh(refreshToken);
        long expiresIn = computeExpiresIn(tokens.accessToken());
        var accessCookie = cookieFactory.issueAccess(tokens.accessToken());
        var refreshCookie = cookieFactory.issueRefresh(tokens.refreshToken());
        AuthDtos.TokenMetaResponse body = AuthDtos.TokenMetaResponse.builder()
                .expiresIn(expiresIn)
                .tokenType("Bearer")
                .build();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(body);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue(name = "refresh_token", required = false) String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REQUIRED, "Refresh token cookie is missing");
        }
        authService.logout(refreshToken);
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, cookieFactory.expireAccess().toString())
                .header(HttpHeaders.SET_COOKIE, cookieFactory.expireRefresh().toString())
                .build();
    }

    @PostMapping("/logout/all")
    public ResponseEntity<Void> logoutAll(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ApiException(ErrorCode.AUTH_FORBIDDEN, "Access token required");
        }
        long userId = Long.parseLong(authentication.getPrincipal().toString());
        authService.logoutAll(userId);
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, cookieFactory.expireAccess().toString())
                .header(HttpHeaders.SET_COOKIE, cookieFactory.expireRefresh().toString())
                .build();
    }

    private long computeExpiresIn(String accessToken) {
        long expiryMillis = tokenService.parseAccess(accessToken).getBody().getExpiration().getTime();
        return Math.max(0, (expiryMillis - System.currentTimeMillis()) / 1000L);
    }
}
