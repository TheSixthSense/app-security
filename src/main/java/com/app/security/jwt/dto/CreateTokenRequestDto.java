package com.app.security.jwt.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotNull;

@Getter
@NoArgsConstructor
public class CreateTokenRequestDto {
    @NotNull
    private long userId;
}
