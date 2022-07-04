package com.app.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class CreateTokenResponseDto {
    private long userId;
    private String token;
}
