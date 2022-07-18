package com.app.security.core.constants;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCode {

    /* 400 BAD_REQUEST : 잘못된 요청 */
    INVALID_CLAIMS(HttpStatus.BAD_REQUEST,  "잘못된 클레임입니다."),
    INVALID_TOKEN(HttpStatus.BAD_REQUEST,  "잘못된 토큰 정보입니다."),
    INVALID_REFRESH_TOKEN(HttpStatus.BAD_REQUEST,  "리프레시 토큰이 유효하지 않습니다."),
    EXPIRED_TOKEN(HttpStatus.BAD_REQUEST,  "만료된 토큰입니다.");

    private final HttpStatus status;
    private final String message;

    ErrorCode(final HttpStatus status, final String message) {
        this.status = status;
        this.message = message;
    }
}
