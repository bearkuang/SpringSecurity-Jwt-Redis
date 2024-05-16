package com.test.login.config.jwt;

public interface JwtVO {
    public static final String SECRET = "abo2"; // HS256 (대칭키)
    public static final int ACCESS_TOKEN_EXPIRATION_TIME = 1000 * 60 * 60 * 1; // 1시간
    public static final int REFRESH_TOKEN_EXPIRATION_TIME = 1000 * 60 * 60 * 24 * 7; // 1주일
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER = "Authorization";
}

