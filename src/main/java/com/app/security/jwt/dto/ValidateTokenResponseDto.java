package com.app.security.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.util.Date;

@Getter
@Builder
@AllArgsConstructor
public class ValidateTokenResponseDto {
    private long userId;
    private String role;
    private Date issuedAt;
    private Date expiredAt;
}
