package kr.co.logintest.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * JWT 관련 설정 바인딩: 시크릿/만료(ISO-8601 문자열).
 */
@Component
public class JwtProperties {
    @Value("${jwt.access.secret:${JWT_ACCESS_SECRET}}")
    public String accessSecret;

    @Value("${jwt.refresh.secret:${JWT_REFRESH_SECRET}}")
    public String refreshSecret;

    @Value("${jwt.access.ttl:${JWT_ACCESS_TTL:PT15M}}")
    public String accessTtl;

    @Value("${jwt.refresh.ttl:${JWT_REFRESH_TTL:P14D}}")
    public String refreshTtl;

    @Value("${jwt.cookie.secure:${JWT_COOKIE_SECURE:false}}")
    public boolean cookieSecure;

    @Value("${jwt.cookie.samesite:${JWT_COOKIE_SAMESITE:Lax}}")
    public String cookieSameSite;

    /** ISO-8601 문자열을 Duration으로 변환 */
    public Duration accessTtlDuration() {
        return Duration.parse(accessTtl);
    }

    /** ISO-8601 문자열을 Duration으로 변환 */
    public Duration refreshTtlDuration() {
        return Duration.parse(refreshTtl);
    }
}
