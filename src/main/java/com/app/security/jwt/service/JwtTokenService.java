package com.app.security.jwt.service;

import com.app.security.core.auth.JwtProvider;
import com.app.security.jwt.domain.enumType.Role;
import com.app.security.jwt.dto.CreateTokenResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JwtTokenService {

    private final JwtProvider jwtProvider;

    public CreateTokenResponseDto createToken(long userId) {
        // TODO : DB select, service로 빼기
        Role role = Role.USER;

        String token = jwtProvider.createToken(userId, role);

        return new CreateTokenResponseDto(userId, token);
    }
}
