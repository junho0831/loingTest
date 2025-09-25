package kr.co.logintest.application.kakao;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import kr.co.logintest.config.KakaoProperties;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

/**
 * 카카오 OAuth2 REST 클라이언트: 코드 교환, 사용자 정보 조회.
 */
@Component
public class KakaoOAuthClient {
    private final RestTemplate rest = new RestTemplate();
    private final KakaoProperties props;

    public KakaoOAuthClient(KakaoProperties props) {
        this.props = props;
    }

    /**
     * Authorization Code → Access Token 교환.
     */
    public TokenResponse exchangeCodeForToken(String code) {
        String url = "https://kauth.kakao.com/oauth/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("client_id", props.clientId);
        if (props.clientSecret != null && !props.clientSecret.isBlank()) {
            form.add("client_secret", props.clientSecret);
        }
        form.add("redirect_uri", props.redirectUri);
        form.add("code", code);
        HttpEntity<MultiValueMap<String, String>> req = new HttpEntity<>(form, headers);
        ResponseEntity<TokenResponse> resp = rest.postForEntity(url, req, TokenResponse.class);
        if (!resp.getStatusCode().is2xxSuccessful() || resp.getBody() == null) {
            throw new IllegalStateException("Failed to exchange code for token");
        }
        return resp.getBody();
    }

    /**
     * 사용자 정보 조회(/v2/user/me).
     */
    public KakaoUserResponse fetchUser(String accessToken) {
        String url = "https://kapi.kakao.com/v2/user/me";
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setAccept(MediaType.parseMediaTypes("application/json"));
        HttpEntity<Void> req = new HttpEntity<>(headers);
        ResponseEntity<KakaoUserResponse> resp = rest.exchange(url, HttpMethod.GET, req, KakaoUserResponse.class);
        if (!resp.getStatusCode().is2xxSuccessful() || resp.getBody() == null) {
            throw new IllegalStateException("Failed to fetch Kakao user");
        }
        return resp.getBody();
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class TokenResponse {
        @JsonProperty("access_token")
        public String accessToken;
        @JsonProperty("token_type")
        public String tokenType;
        @JsonProperty("refresh_token")
        public String refreshToken;
        @JsonProperty("expires_in")
        public Long expiresIn;
        @JsonProperty("scope")
        public String scope;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class KakaoUserResponse {
        public Long id;
        @JsonProperty("kakao_account")
        public KakaoAccount kakaoAccount;

        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class KakaoAccount {
            public String email;
            public Profile profile;

            @JsonIgnoreProperties(ignoreUnknown = true)
            public static class Profile {
                public String nickname;
                @JsonProperty("profile_image_url")
                public String profileImageUrl;
            }
        }
    }
}
