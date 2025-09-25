package kr.co.logintest.error;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

/**
 * 전역 예외 처리: 검증 오류/도메인 예외를 표준 JSON 포맷으로 변환.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    /**
     * @Valid/@Validated 바인딩 오류 처리(필드별 메시지 포함).
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(HttpServletRequest req, MethodArgumentNotValidException ex) {
        Map<String, String> fieldErrors = new HashMap<>();
        for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.put(fe.getField(), fe.getDefaultMessage());
        }
        var body = ApiError.of(req.getRequestURI(), ErrorCode.VALIDATION_ERROR, null, fieldErrors);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    /**
     * 파라미터/경로 변수 제약 위반 처리.
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiError> handleConstraint(HttpServletRequest req, ConstraintViolationException ex) {
        var body = ApiError.of(req.getRequestURI(), ErrorCode.VALIDATION_ERROR, ex.getMessage(), null);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    /**
     * 도메인/비즈니스 예외 처리.
     */
    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiError> handleApi(HttpServletRequest req, ApiException ex) {
        var body = ApiError.of(req.getRequestURI(), ex.getErrorCode(), ex.getMessage(), ex.getDetails());
        return ResponseEntity.status(ex.getErrorCode().status).body(body);
    }

    /**
     * 예상치 못한 서버 오류 처리(500).
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleOther(HttpServletRequest req, Exception ex) {
        var body = ApiError.of(req.getRequestURI(), ErrorCode.SERVER_ERROR, ex.getMessage(), null);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}
