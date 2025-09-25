package kr.co.logintest.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.co.logintest.error.ApiError;
import kr.co.logintest.error.ErrorCode;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 인가 실패(권한 부족)를 JSON 형식으로 응답하는 핸들러.
 */
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        ErrorCode ec = ErrorCode.AUTH_FORBIDDEN;
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
