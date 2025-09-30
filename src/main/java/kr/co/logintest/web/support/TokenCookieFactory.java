package kr.co.logintest.web.support;

import kr.co.logintest.config.JwtProperties;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Locale;

/**
 * Access/Refresh 토큰을 HttpOnly 쿠키로 발급/폐기하는 헬퍼.
 */
@Component
public class TokenCookieFactory {
    private final JwtProperties jwtProperties;

    public TokenCookieFactory(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    public ResponseCookie issueAccess(String accessToken) {
        return baseCookie("access_token", accessToken)
                .maxAge(jwtProperties.accessTtlDuration())
                .build();
    }

    public ResponseCookie expireAccess() {
        return baseCookie("access_token", "")
                .maxAge(Duration.ZERO)
                .build();
    }

    public ResponseCookie issueRefresh(String refreshToken) {
        return baseCookie("refresh_token", refreshToken)
                .maxAge(jwtProperties.refreshTtlDuration())
                .build();
    }

    public ResponseCookie expireRefresh() {
        return baseCookie("refresh_token", "")
                .maxAge(Duration.ZERO)
                .build();
    }

    private ResponseCookie.ResponseCookieBuilder baseCookie(String name, String value) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(jwtProperties.cookieSecure)
                .sameSite(resolveSameSite())
                .path("/");
    }

    private String resolveSameSite() {
        String sameSite = jwtProperties.cookieSameSite;
        if (sameSite == null || sameSite.isBlank()) {
            return "Lax";
        }
        String normalized = sameSite.trim();
        String upper = normalized.toUpperCase(Locale.ROOT);
        return switch (upper) {
            case "STRICT" -> "Strict";
            case "NONE" -> "None";
            default -> "Lax";
        };
    }
}
