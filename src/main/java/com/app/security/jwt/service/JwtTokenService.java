package com.app.security.jwt.service;

import com.app.security.core.auth.JwtProvider;
import com.app.security.jwt.dto.CreateTokenRequestDto;
import com.app.security.jwt.dto.CreateTokenResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JwtTokenService {

    private final JwtProvider jwtProvider;

    public CreateTokenResponseDto createToken(CreateTokenRequestDto requestDto) {

        String accessToken = jwtProvider.createAccessToken(requestDto);
        String refreshToken = jwtProvider.createRefreshToken(requestDto);

        // TODO. 토큰 DB 저장

        return CreateTokenResponseDto.builder()
                .userId(requestDto.getUserId())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
}
