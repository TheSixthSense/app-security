package com.app.security.jwt.service;

import com.app.security.core.auth.JwtProvider;
import com.app.security.jwt.domain.enumType.Role;
import com.app.security.jwt.dto.CreateTokenRequestDto;
import com.app.security.jwt.dto.CreateTokenResponseDto;
import com.app.security.jwt.dto.RefreshTokenRequestDto;
import com.app.security.jwt.dto.RefreshTokenResponseDto;
import io.jsonwebtoken.Claims;
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

    public RefreshTokenResponseDto refreshToken(RefreshTokenRequestDto requestDto) {
        String token = requestDto.getRefreshToken();

        jwtProvider.validateToken(token);

        Claims claims = jwtProvider.parseClaims(token);
        Long userId = Long.parseLong(claims.get("user_id").toString());

        // TODO. 토큰 DB 검증 및 저장

        String newToken = jwtProvider.createRefreshToken(new CreateTokenRequestDto(userId, Role.USER));

        return RefreshTokenResponseDto.builder()
                .userId(userId)
                .refreshToken(newToken)
                .build();
    }
}
