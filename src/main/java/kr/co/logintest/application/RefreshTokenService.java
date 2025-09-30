package kr.co.logintest.application;

import kr.co.logintest.domain.RefreshToken;
import kr.co.logintest.domain.User;
import kr.co.logintest.error.ApiException;
import kr.co.logintest.error.ErrorCode;
import kr.co.logintest.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokens;

    public RefreshTokenService(RefreshTokenRepository refreshTokens) {
        this.refreshTokens = refreshTokens;
    }

    /**
     * Refresh 토큰 신규 발급 시 jti를 생성하고 저장한다.
     */
    @Transactional
    public RefreshToken register(User user, Instant expiresAt) {
        String jti = UUID.randomUUID().toString();
        RefreshToken token = RefreshToken.builder()
                .user(user)
                .jti(jti)
                .expiresAt(expiresAt)
                .revoked(false)
                .build();
        return refreshTokens.save(token);
    }

    /**
     * 저장된 토큰을 조회한다. 없거나 비활성화된 경우 예외를 던진다.
     */
    @Transactional(readOnly = true)
    public RefreshToken findActiveByJti(String jti, Instant now) {
        RefreshToken token = refreshTokens.findByJti(jti)
                .orElseThrow(() -> new ApiException(ErrorCode.AUTH_REFRESH_REVOKED, "Refresh token not found"));
        if (token.isExpired(now)) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REVOKED, "Refresh token expired");
        }
        if (token.isRevoked()) {
            throw new ApiException(ErrorCode.AUTH_REFRESH_REVOKED, "Refresh token already revoked");
        }
        return token;
    }

    /**
     * Refresh 토큰을 즉시 무효화한다.
     */
    @Transactional
    public void revoke(RefreshToken token, Instant when) {
        token.revoke(when);
    }

    /**
     * 특정 사용자의 모든 Refresh 토큰을 무효화한다.
     */
    @Transactional
    public void revokeAll(User user, Instant when) {
        refreshTokens.revokeAllByUserId(user.getId(), when);
    }

}
