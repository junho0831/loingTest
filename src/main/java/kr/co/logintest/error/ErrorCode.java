package kr.co.logintest.error;

public enum ErrorCode {
    AUTH_INVALID_CREDENTIALS(401, "AUTH_INVALID_CREDENTIALS", "Invalid email or password"),
    AUTH_TOKEN_EXPIRED(401, "AUTH_TOKEN_EXPIRED", "Token expired"),
    AUTH_REFRESH_REVOKED(401, "AUTH_REFRESH_REVOKED", "Refresh token revoked or invalid"),
    AUTH_FORBIDDEN(403, "AUTH_FORBIDDEN", "Forbidden"),
    DUPLICATE_EMAIL(409, "DUPLICATE_EMAIL", "Email already exists"),
    VALIDATION_ERROR(400, "VALIDATION_ERROR", "Validation failed"),
    NOT_FOUND(404, "NOT_FOUND", "Resource not found"),
    SERVER_ERROR(500, "SERVER_ERROR", "Internal server error");

    public final int status;
    public final String code;
    public final String defaultMessage;

    ErrorCode(int status, String code, String defaultMessage) {
        this.status = status;
        this.code = code;
        this.defaultMessage = defaultMessage;
    }
}

