package com.example.springsecuritydemo.service.jwt;

public class AccessTokenResponse {
    private String tokenType = "Bearer";
    private String accessToken;
    private String refreshToken;

    public AccessTokenResponse(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}

