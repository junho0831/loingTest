package kr.co.logintest.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 카카오 OAuth 설정 바인딩: 클라이언트 ID/Secret, 리다이렉트 URI, 프론트 리다이렉트 URI.
 */
@Component
public class KakaoProperties {
    @Value("${kakao.client-id:${KAKAO_CLIENT_ID:}}")
    public String clientId;

    @Value("${kakao.client-secret:${KAKAO_CLIENT_SECRET:}}")
    public String clientSecret; // 선택

    @Value("${kakao.redirect-uri:${KAKAO_REDIRECT_URI:http://localhost:8080/login/oauth2/code/kakao}}")
    public String redirectUri; // 카카오에 등록된 콜백 URL

    @Value("${app.front-redirect-uri:${APP_FRONT_REDIRECT_URI:}}")
    public String frontRedirectUri; // 선택: JWT 발급 후 프론트로 리다이렉트할 URL
}
