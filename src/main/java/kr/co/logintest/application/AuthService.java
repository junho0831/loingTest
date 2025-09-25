package kr.co.logintest.application;

import io.jsonwebtoken.Claims;
import kr.co.logintest.domain.AuthProvider;
import kr.co.logintest.domain.Role;
import kr.co.logintest.domain.User;
import kr.co.logintest.error.ApiException;
import kr.co.logintest.error.ErrorCode;
import kr.co.logintest.repository.UserRepository;
import kr.co.logintest.web.dto.AuthDtos;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

/**
 * 인증 유스케이스 서비스.
 * - 회원가입(이메일 중복 체크, BCrypt 해싱)
 * - 로그인(자격 검증 후 JWT 발급)
 * - 토큰 갱신(Refresh 검증 + tokenVersion 정책)
 * - 로그아웃(서버 측 무효화: tokenVersion 증가)
 */
@Service
public class AuthService {
    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final JwtTokenService tokens;

    public AuthService(UserRepository users, PasswordEncoder encoder, JwtTokenService tokens) {
        this.users = users;
        this.encoder = encoder;
        this.tokens = tokens;
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
    @Transactional(readOnly = true)
    public Map<String, Object> login(AuthDtos.LoginRequest req) {
        User user = users.findByEmail(req.getEmail())
                .orElseThrow(() -> new ApiException(ErrorCode.AUTH_INVALID_CREDENTIALS));
        if (user.getPasswordHash() == null || !encoder.matches(req.getPassword(), user.getPasswordHash())) {
            throw new ApiException(ErrorCode.AUTH_INVALID_CREDENTIALS);
        }
        String access = tokens.generateAccessToken(user.getId(), user.getEmail(), user.getRole());
        String refresh = tokens.generateRefreshToken(user.getId(), user.getEmail(), user.getTokenVersion());
        return Map.of(
                "access", access,
                "refresh", refresh
        );
    }

    /**
     * 토큰 갱신: Refresh 유효성 + typ=refresh 확인, tokenVersion 일치 시 재발급.
     */
    @Transactional
    public Map<String, Object> refresh(String refreshToken) {
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
        int tokenVersion = (Integer) claims.get("tv");

        User user = users.findById(userId).orElseThrow(() -> new ApiException(ErrorCode.AUTH_REFRESH_REVOKED));
        if (user.getTokenVersion() != tokenVersion) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REVOKED, "Token version mismatch");
        }

        String access = tokens.generateAccessToken(user.getId(), user.getEmail(), user.getRole());
        // Issue new refresh with same version (rotation policy could be applied here)
        String refresh = tokens.generateRefreshToken(user.getId(), user.getEmail(), user.getTokenVersion());
        return Map.of("access", access, "refresh", refresh);
    }

    /**
     * 로그아웃: 해당 사용자의 tokenVersion 증가 → 기존 Refresh 전부 무효화.
     */
    @Transactional
    public void logout(String refreshToken) {
        Claims claims;
        try {
            claims = tokens.parseRefresh(refreshToken).getBody();
        } catch (Exception e) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REVOKED, "Invalid refresh token");
        }
        long userId = Long.parseLong(claims.getSubject());
        User user = users.findById(userId).orElseThrow(() -> new ApiException(ErrorCode.AUTH_REFRESH_REVOKED));
        user.setTokenVersion(user.getTokenVersion() + 1);
        users.save(user);
    }
}
