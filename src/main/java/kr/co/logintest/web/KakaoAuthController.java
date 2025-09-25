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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

/**
 * 카카오 로그인 엔드포인트.
 * - /auth/kakao/login: state 쿠키 설정 후 카카오 인가 페이지로 리다이렉트
 * - /auth/kakao/callback: 코드 교환 처리, 내부 JWT 발급(JSON 또는 프론트 리다이렉트)
 */
@RestController
@RequestMapping("/auth/kakao")
public class KakaoAuthController {
    private final KakaoAuthService kakaoAuthService;
    private final KakaoProperties props;

    public KakaoAuthController(KakaoAuthService kakaoAuthService, KakaoProperties props) {
        this.kakaoAuthService = kakaoAuthService;
        this.props = props;
    }

    @GetMapping("/login")
    public ResponseEntity<Void> login(HttpServletResponse response) {
        String state = generateState();
        setStateCookie(response, state);
        String url = kakaoAuthService.buildAuthorizeUrl(state);
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(java.net.URI.create(url));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    @GetMapping("/callback")
    public ResponseEntity<?> callback(
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
            // CSRF 방지: state 불일치 시 거절
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_state"));
        }
        clearStateCookie(response);

        var tokens = kakaoAuthService.handleCallback(code);

        // 선택: 프론트 리다이렉트가 설정되어 있으면 URL 해시(#)에 토큰을 담아 전달
        if (props.frontRedirectUri != null && !props.frontRedirectUri.isBlank()) {
            String redirect = props.frontRedirectUri + "#accessToken=" + url(tokens.get("access")) +
                    "&refreshToken=" + url(tokens.get("refresh"));
            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(java.net.URI.create(redirect));
            return new ResponseEntity<>(headers, HttpStatus.FOUND);
        }

        // 기본: JSON으로 토큰 반환
        return ResponseEntity.ok(AuthDtos.TokenResponse.builder()
                .accessToken(tokens.get("access"))
                .refreshToken(tokens.get("refresh"))
                .expiresIn(0)
                .build());
    }

    private String generateState() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private void setStateCookie(HttpServletResponse response, String state) {
        Cookie cookie = new Cookie("k_state", state);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(300); // 5분
        // SameSite=Lax (서블릿 표준에는 직접 설정 필드가 없어 헤더로 처리 필요할 수 있으나 간략화)
        response.addCookie(cookie);
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

    private String url(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }
}
