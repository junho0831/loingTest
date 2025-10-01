package kr.co.logintest.application;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import kr.co.logintest.config.JwtProperties;
import kr.co.logintest.domain.Role;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

/**
 * JWT Access/Refresh 토큰 생성/검증 서비스.
 * - HS256 서명, 키는 환경변수/설정에서 주입(JwtProperties)
 * - Base64 문자열/일반 문자열 모두 지원(먼저 Base64 시도 후 실패 시 raw 바이트 사용)
 */
@Service
public class JwtTokenService {
    private final JwtProperties props;
    private Key accessKey;
    private Key refreshKey;

    public JwtTokenService(JwtProperties props) {
        this.props = props;
    }

    /**
     * 애플리케이션 시작 시 서명 키 초기화.
     */
    @PostConstruct
    void init() {
        accessKey = toKey(props.accessSecret);
        refreshKey = toKey(props.refreshSecret);
    }

    private Key toKey(String secret) {
        // Base64 또는 일반 문자열 모두 허용. 먼저 Base64 디코딩을 시도.
        try {
            return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        } catch (Exception e) {
            return Keys.hmacShaKeyFor(secret.getBytes());
        }
    }

    /**
     * Access 토큰 생성: sub(userId), email, role, typ=access, iat/exp 포함
     */
    public String generateAccessToken(long userId, String email, Role role) {
        Instant now = Instant.now();
        Instant exp = now.plus(props.accessTtlDuration());
        return Jwts.builder()
                .setSubject(Long.toString(userId))
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(exp))
                .claim("email", email)
                .claim("role", role.name())
                .claim("typ", "access")
                .signWith(accessKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Refresh 토큰 생성: sub(userId), email, tv(tokenVersion), jti, typ=refresh, iat/exp 포함
     */
    public String generateRefreshToken(long userId, String email, int tokenVersion, String jti) {
        Instant now = Instant.now();
        Instant exp = now.plus(props.refreshTtlDuration());
        return Jwts.builder()
                .setSubject(Long.toString(userId))
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(exp))
                .setId(jti)
                .claim("email", email)
                .claim("tv", tokenVersion)
                .claim("typ", "refresh")
                .signWith(refreshKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Access 토큰 파싱/검증(서명/만료 확인).
     */
    public Jws<Claims> parseAccess(String token) {
        return Jwts.parserBuilder().setSigningKey(accessKey).build().parseClaimsJws(token);
    }

    /**
     * Refresh 토큰 파싱/검증(서명/만료 확인).
     */
    public Jws<Claims> parseRefresh(String token) {
        return Jwts.parserBuilder().setSigningKey(refreshKey).build().parseClaimsJws(token);
    }
}
