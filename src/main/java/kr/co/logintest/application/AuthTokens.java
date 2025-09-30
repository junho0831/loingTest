package kr.co.logintest.application;

/**
 * Access/Refresh 토큰 문자열 묶음.
 */
public record AuthTokens(String accessToken, String refreshToken) {
}
