package kr.co.logintest.web;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.co.logintest.application.AuthTokens;
import kr.co.logintest.application.kakao.KakaoAuthService;
import kr.co.logintest.config.KakaoProperties;
import kr.co.logintest.web.support.TokenCookieFactory;
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
    private final TokenCookieFactory cookieFactory;

    public KakaoAuthController(KakaoAuthService kakaoAuthService, KakaoProperties props, TokenCookieFactory cookieFactory) {
        this.kakaoAuthService = kakaoAuthService;
        this.props = props;
        this.cookieFactory = cookieFactory;
    }

    @GetMapping("/login")
    public ResponseEntity<Void> login(HttpServletResponse response,
                                      @RequestParam(name = "redirect", required = false) String redirect) {
        String state = generateState();
        setStateCookie(response, state);
        setRedirectCookie(response, sanitizeRedirect(redirect));
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

        AuthTokens tokens = kakaoAuthService.handleCallback(code);

        // 기본: 홈(/) 또는 지정된 프론트/요청 redirect로 리다이렉트하며 해시에 토큰 전달
        String cookieRedirect = readRedirectCookie(request);
        clearRedirectCookie(response);
        String front = resolveFrontRedirect(cookieRedirect);
        String redirect = front + "#login=success";
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(java.net.URI.create(redirect));
        headers.add(HttpHeaders.SET_COOKIE, cookieFactory.issueAccess(tokens.accessToken()).toString());
        headers.add(HttpHeaders.SET_COOKIE, cookieFactory.issueRefresh(tokens.refreshToken()).toString());
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
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

    private void setRedirectCookie(HttpServletResponse response, String redirect) {
        if (redirect == null) return;
        Cookie cookie = new Cookie("k_redir", redirect);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(300);
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
        // 보안: 동일 오리진 경로만 허용. 절대 URL, //로 시작하는 경우 무시
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
