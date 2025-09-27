package kr.co.logintest.web;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.co.logintest.application.kakao.KakaoAuthService;
import kr.co.logintest.config.KakaoProperties;
import kr.co.logintest.web.dto.AuthDtos;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 호환용 콜백 엔드포인트: /login/oauth2/code/kakao
 * - Spring Security OAuth2 기본 경로와 동일하게 맞춰 사용하려는 경우를 위해 제공.
 * - 실제 인가는 KakaoAuthService.handleCallback(code)에 위임.
 */
@RestController
public class KakaoOAuth2CompatController {
    private final KakaoAuthService kakaoAuthService;
    private final KakaoProperties props;

    public KakaoOAuth2CompatController(KakaoAuthService kakaoAuthService, KakaoProperties props) {
        this.kakaoAuthService = kakaoAuthService;
        this.props = props;
    }

    @GetMapping("/login/oauth2/code/kakao")
    public ResponseEntity<?> loginOauth2CodeKakao(
            @RequestParam(name = "code", required = false) String code,
            @RequestParam(name = "state", required = false) String state,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        if (code == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "missing_code"));
        }
        String cookieState = readStateCookie(request);
        if (cookieState != null && state != null && !cookieState.equals(state)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_state"));
        }
        clearStateCookie(response);

        var tokens = kakaoAuthService.handleCallback(code);

        String cookieRedirect = readRedirectCookie(request);
        clearRedirectCookie(response);
        String front = resolveFrontRedirect(cookieRedirect);
        String redirect = front + "#accessToken=" + url(tokens.get("access")) +
                "&refreshToken=" + url(tokens.get("refresh"));
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(java.net.URI.create(redirect));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    private String readStateCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        for (Cookie c : request.getCookies()) {
            if ("k_state".equals(c.getName())) return c.getValue();
        }
        return null;
    }

    private void clearStateCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("k_state", "");
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    private String readRedirectCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        for (Cookie c : request.getCookies()) {
            if ("k_redir".equals(c.getName())) return c.getValue();
        }
        return null;
    }

    private void clearRedirectCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("k_redir", "");
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    private String sanitizeRedirect(String redirect) {
        if (redirect == null || redirect.isBlank()) return null;
        if (!redirect.startsWith("/") || redirect.startsWith("//")) return null;
        return redirect;
    }

    private String resolveFrontRedirect(String cookieRedirect) {
        String front = (props.frontRedirectUri != null && !props.frontRedirectUri.isBlank())
                ? props.frontRedirectUri
                : "/";
        String safe = sanitizeRedirect(cookieRedirect);
        return (safe != null ? safe : front);
    }

    private String url(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }
}
