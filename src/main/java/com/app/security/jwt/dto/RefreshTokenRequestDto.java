package com.app.security.jwt.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotNull;

@Getter
@NoArgsConstructor
public class RefreshTokenRequestDto {
    @NotNull
    private long userId;
    private String refreshToken;
}
