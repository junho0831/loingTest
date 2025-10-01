package kr.co.logintest.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.co.logintest.application.JwtTokenService;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

/**
 * 요청 헤더의 Bearer Access 토큰을 파싱하여 인증 컨텍스트를 채우는 필터.
 * - 만료/무효 토큰일 경우 요청 속성에 오류 코드를 담아 EntryPoint에서 JSON 응답 생성.
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtTokenService tokenService;

    public JwtAuthFilter(JwtTokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = resolveToken(request);
        if (token != null) {
            try {
                Jws<Claims> jws = tokenService.parseAccess(token);
                Claims c = jws.getBody();
                String typ = c.get("typ", String.class);
                if (!"access".equals(typ)) {
                    request.setAttribute("auth_error_code", "invalid");
                } else {
                    String role = (String) c.get("role");
                    Collection<? extends GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));
                    var authToken = new JwtAuthentication(c.getSubject(), (String) c.get("email"), authorities);
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            } catch (io.jsonwebtoken.ExpiredJwtException ex) {
                // 만료 토큰: 인증 실패로 처리하되, 에러 코드는 expired로 설정
                request.setAttribute("auth_error_code", "expired");
            } catch (Exception ignored) {
                // 서명 오류 등 기타 예외: invalid로 처리
                request.setAttribute("auth_error_code", "invalid");
            }
        }
        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String auth = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (auth != null && auth.startsWith("Bearer ")) {
            return auth.substring(7);
        }
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("access_token".equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isBlank()) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    static class JwtAuthentication extends AbstractAuthenticationToken {
        private final String userId;
        private final String email;

        JwtAuthentication(String userId, String email, Collection<? extends GrantedAuthority> authorities) {
            super(authorities);
            this.userId = userId;
            this.email = email;
            setAuthenticated(true);
        }

        @Override
        public Object getCredentials() { return "N/A"; }

        @Override
        public Object getPrincipal() { return userId; }

        public String getEmail() { return email; }
    }
}
