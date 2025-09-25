package kr.co.logintest.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * JWT 관련 설정 바인딩: 시크릿/만료(ISO-8601 문자열).
 */
@Component
public class JwtProperties {
    @Value("${jwt.access.secret:${JWT_ACCESS_SECRET:change-me-access}}")
    public String accessSecret;

    @Value("${jwt.refresh.secret:${JWT_REFRESH_SECRET:change-me-refresh}}")
    public String refreshSecret;

    @Value("${jwt.access.ttl:${JWT_ACCESS_TTL:PT15M}}")
    public String accessTtl;

    @Value("${jwt.refresh.ttl:${JWT_REFRESH_TTL:P14D}}")
    public String refreshTtl;

    /** ISO-8601 문자열을 Duration으로 변환 */
    public Duration accessTtlDuration() {
        return Duration.parse(accessTtl);
    }

    /** ISO-8601 문자열을 Duration으로 변환 */
    public Duration refreshTtlDuration() {
        return Duration.parse(refreshTtl);
    }
}
