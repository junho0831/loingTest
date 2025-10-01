package kr.co.logintest.application;

import io.jsonwebtoken.Claims;
import kr.co.logintest.config.JwtProperties;
import kr.co.logintest.domain.AuthProvider;
import kr.co.logintest.domain.RefreshToken;
import kr.co.logintest.domain.Role;
import kr.co.logintest.domain.User;
import kr.co.logintest.error.ApiException;
import kr.co.logintest.error.ErrorCode;
import kr.co.logintest.repository.UserRepository;
import kr.co.logintest.web.dto.AuthDtos;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

import static java.util.Objects.isNull;

/**
 * 인증 유스케이스 서비스.
 * - 회원가입(이메일 중복 체크, BCrypt 해싱)
 * - 로그인(자격 검증 후 JWT 발급)
 * - 토큰 갱신(Refresh 검증 + tokenVersion 정책)
 * - 로그아웃(단일 기기 jti 폐기 / 전체 로그아웃 시 tokenVersion 증가)
 */
@Service
public class AuthService {
    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final JwtTokenService tokens;
    private final RefreshTokenService refreshTokens;
    private final JwtProperties jwtProperties;

    public AuthService(UserRepository users, PasswordEncoder encoder, JwtTokenService tokens,
                       RefreshTokenService refreshTokens, JwtProperties jwtProperties) {
        this.users = users;
        this.encoder = encoder;
        this.tokens = tokens;
        this.refreshTokens = refreshTokens;
        this.jwtProperties = jwtProperties;
    }

    /**
     * 회원가입: 이메일 중복 검사 후 사용자 생성.
     */
    @Transactional
    public User register(AuthDtos.RegisterRequest req) {
        if (users.existsByEmail(req.getEmail())) {
            throw new ApiException(ErrorCode.DUPLICATE_EMAIL);
        }
        User user = User.builder()
                .email(req.getEmail())
                .passwordHash(encoder.encode(req.getPassword()))
                .name(req.getName())
                .role(Role.USER)
                .provider(AuthProvider.LOCAL)
                .providerId(null)
                .tokenVersion(0)
                .build();
        return users.save(user);
    }

    /**
     * 로그인: 비밀번호 검증 후 Access/Refresh 발급.
     */
    @Transactional
    public AuthTokens login(AuthDtos.LoginRequest req) {
        User user = users.findByEmail(req.getEmail())
                .orElseThrow(() -> new ApiException(ErrorCode.AUTH_INVALID_CREDENTIALS));
        if (user.getPasswordHash() == null || !encoder.matches(req.getPassword(), user.getPasswordHash())) {
            throw new ApiException(ErrorCode.AUTH_INVALID_CREDENTIALS);
        }
        String access = tokens.generateAccessToken(user.getId(), user.getEmail(), user.getRole());
        String refresh = issueRefreshToken(user);
        return new AuthTokens(access, refresh);
    }

    /**
     * 토큰 갱신: Refresh 유효성 + typ=refresh 확인, tokenVersion 일치 시 재발급.
     */
    @Transactional
    public AuthTokens refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REQUIRED, "Refresh token cookie is missing");
        }
        Claims claims;
        try {
            claims = tokens.parseRefresh(refreshToken).getBody();
        } catch (Exception e) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REVOKED, "Invalid refresh token");
        }
        if (!"refresh".equals(claims.get("typ"))) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REVOKED, "Not a refresh token");
        }
        long userId = Long.parseLong(claims.getSubject());
        Number tokenVersionClaim = (Number) claims.get("tv");
        if (tokenVersionClaim == null) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REVOKED, "Token version missing");
        }
        String jti = claims.getId();
        if (isNull(jti) || jti.isBlank()) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REVOKED, "Token id missing");
        }

        User user = users.findById(userId).orElseThrow(() -> new ApiException(ErrorCode.AUTH_REFRESH_REVOKED));
        if (user.getTokenVersion() != tokenVersionClaim.intValue()) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REVOKED, "Token version mismatch");
        }

        var now = Instant.now();
        var stored = refreshTokens.findActiveByJti(jti, now);
        if (!stored.getUser().getId().equals(userId)) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REVOKED, "Refresh token user mismatch");
        }

        refreshTokens.revoke(stored, now);

        String access = tokens.generateAccessToken(user.getId(), user.getEmail(), user.getRole());
        String refreshed = issueRefreshToken(user);
        return new AuthTokens(access, refreshed);
    }

    /**
     * 로그아웃: 전달된 Refresh 토큰(jti)만 무효화.
     */
    @Transactional
    public void logout(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REQUIRED, "Refresh token cookie is missing");
        }
        Claims claims;
        try {
            claims = tokens.parseRefresh(refreshToken).getBody();
        } catch (Exception e) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REVOKED, "Invalid refresh token");
        }
        long userId = Long.parseLong(claims.getSubject());
        String jti = claims.getId();
        if (isNull(jti) || jti.isBlank()) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REVOKED, "Token id missing");
        }

        Instant now = Instant.now();
        RefreshToken token = refreshTokens.findActiveByJti(jti, now);
        if (!token.getUser().getId().equals(userId)) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REVOKED, "Refresh token user mismatch");
        }
        refreshTokens.revoke(token, now);
    }

    /**
     * 전체 로그아웃: tokenVersion 증가 + 저장된 Refresh 토큰 전량 폐기.
     */
    @Transactional
    public void logoutAll(long userId) {
        User user = users.findById(userId)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND, "User not found"));
        user.setTokenVersion(user.getTokenVersion() + 1);
        refreshTokens.revokeAll(user, Instant.now());
    }

    private String issueRefreshToken(User user) {
        Instant expiresAt = Instant.now().plus(jwtProperties.refreshTtlDuration());
        var registered = refreshTokens.register(user, expiresAt);
        return tokens.generateRefreshToken(user.getId(), user.getEmail(), user.getTokenVersion(), registered.getJti());
    }
}
