package com.app.security.service;

import com.app.security.EnumType;
import com.app.security.auth.JwtProvider;
import com.app.security.dto.CreateTokenResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JwtTokenService {

    private final JwtProvider jwtProvider;

    public CreateTokenResponseDto createToken(long userId) {
        // TODO : DB select, service로 빼기
        EnumType.ROLE role = EnumType.ROLE.USER;

        String token = jwtProvider.createToken(userId, role);

        return new CreateTokenResponseDto(userId, token);
    }
}
