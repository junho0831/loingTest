package kr.co.logintest.error;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
public class ApiError {
    private Instant timestamp;
    private String path;
    private int status;
    private String code;
    private String message;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Object details;

    public static ApiError of(String path, ErrorCode ec, String message, Object details) {
        return ApiError.builder()
                .timestamp(Instant.now())
                .path(path)
                .status(ec.status)
                .code(ec.code)
                .message(message != null ? message : ec.defaultMessage)
                .details(details)
                .build();
    }
}

