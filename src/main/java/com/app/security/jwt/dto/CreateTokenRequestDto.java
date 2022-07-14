package com.app.security.jwt.dto;

import com.app.security.jwt.domain.enumType.Role;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotNull;

@Getter
@NoArgsConstructor
public class CreateTokenRequestDto {
    @NotNull
    private long userId;
    private Role role = Role.USER;
}
