package com.app.security.jwt.dto;

import com.app.security.jwt.domain.enumType.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotNull;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CreateTokenRequestDto {
    @NotNull
    private long userId;
    private Role role = Role.USER;

    public CreateTokenRequestDto(long userId) {
        this.userId = userId;
        this.role = Role.USER;
    }
}
