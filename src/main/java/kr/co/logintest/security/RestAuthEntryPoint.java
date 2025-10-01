package kr.co.logintest.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.co.logintest.error.ApiError;
import kr.co.logintest.error.ErrorCode;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 미인증/만료 등의 인증 실패를 JSON 형식으로 응답하는 EntryPoint.
 */
@Component
public class RestAuthEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        Object codeAttr = request.getAttribute("auth_error_code");
        ErrorCode ec;
        if ("expired".equals(codeAttr)) {
            ec = ErrorCode.AUTH_TOKEN_EXPIRED;
        } else if ("invalid".equals(codeAttr)) {
            ec = ErrorCode.AUTH_TOKEN_INVALID;
        } else {
            ec = ErrorCode.AUTH_INVALID_CREDENTIALS;
        }
        response.setStatus(ec.status);
        response.setContentType("application/json;charset=UTF-8");
        var body = ApiError.of(request.getRequestURI(), ec, ec.defaultMessage, null);
        String json = "{\"timestamp\":\"" + body.getTimestamp() + "\"," +
                "\"path\":\"" + body.getPath() + "\"," +
                "\"status\":" + body.getStatus() + "," +
                "\"code\":\"" + body.getCode() + "\"," +
                "\"message\":\"" + body.getMessage().replace("\"","\\\"") + "\"}";
        response.getWriter().write(json);
    }
}
