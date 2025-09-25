package kr.co.logintest.application.kakao;

import kr.co.logintest.application.JwtTokenService;
import kr.co.logintest.config.KakaoProperties;
import kr.co.logintest.domain.AuthProvider;
import kr.co.logintest.domain.Role;
import kr.co.logintest.domain.User;
import kr.co.logintest.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

/**
 * 카카오 OAuth2 연동 서비스: 인가 URL 생성, 콜백 처리(코드 교환/사용자 조회/내부 사용자 연결 및 JWT 발급).
 */
@Service
public class KakaoAuthService {
    private final KakaoOAuthClient client;
    private final KakaoProperties props;
    private final UserRepository users;
    private final JwtTokenService tokens;

    public KakaoAuthService(KakaoOAuthClient client, KakaoProperties props, UserRepository users, JwtTokenService tokens) {
        this.client = client;
        this.props = props;
        this.users = users;
        this.tokens = tokens;
    }

    /**
     * 카카오 인가 URL 구성. state는 CSRF 방지용.
     */
    public String buildAuthorizeUrl(String state) {
        // https://kauth.kakao.com/oauth/authorize?client_id=xxx&redirect_uri=xxx&response_type=code&state=yyy
        String base = "https://kauth.kakao.com/oauth/authorize";
        return base + "?response_type=code" +
                "&client_id=" + url(props.clientId) +
                "&redirect_uri=" + url(props.redirectUri) +
                (state != null ? "&state=" + url(state) : "");
    }

    /**
     * 콜백 처리: 토큰 교환 → 사용자 조회 → 내부 사용자 연결/최초 생성 → 내부 JWT 발급.
     */
    @Transactional
    public Map<String, String> handleCallback(String code) {
        var token = client.exchangeCodeForToken(code);
        var kakaoUser = client.fetchUser(token.accessToken);

        String providerId = kakaoUser.id != null ? kakaoUser.id.toString() : null;
        if (providerId == null) throw new IllegalStateException("Kakao id missing");

        User user = users.findByProviderAndProviderId(AuthProvider.KAKAO, providerId).orElse(null);

        if (user == null) {
            String email = kakaoUser.kakaoAccount != null ? kakaoUser.kakaoAccount.email : null;
            if (email == null || email.isBlank()) {
                email = "kakao_" + providerId + "@kakao.local"; // 정책: 이메일 미제공 시 대체 식별자 생성
            }
            String name = (kakaoUser.kakaoAccount != null && kakaoUser.kakaoAccount.profile != null && kakaoUser.kakaoAccount.profile.nickname != null)
                    ? kakaoUser.kakaoAccount.profile.nickname
                    : ("KakaoUser" + providerId.substring(Math.max(0, providerId.length() - 6)));

            user = User.builder()
                    .email(email)
                    .passwordHash(null)
                    .name(name)
                    .role(Role.USER)
                    .provider(AuthProvider.KAKAO)
                    .providerId(providerId)
                    .tokenVersion(0)
                    .build();
            user = users.save(user);
        }

        String access = tokens.generateAccessToken(user.getId(), user.getEmail(), user.getRole());
        String refresh = tokens.generateRefreshToken(user.getId(), user.getEmail(), user.getTokenVersion());
        return Map.of("access", access, "refresh", refresh);
    }

    private String url(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }
}
