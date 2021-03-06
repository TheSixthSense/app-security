package com.app.security.jwt.service;

import com.app.security.core.auth.JwtProvider;
import com.app.security.core.exception.JWTException;
import com.app.security.jwt.domain.enumType.Role;
import com.app.security.jwt.dto.CreateTokenRequestDto;
import com.app.security.jwt.dto.CreateTokenResponseDto;
import com.app.security.jwt.dto.RefreshTokenRequestDto;
import com.app.security.jwt.dto.RefreshTokenResponseDto;
import com.app.security.jwt.entity.RefreshToken;
import com.app.security.jwt.repository.RefreshTokenRepository;
import com.app.security.util.DateUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Optional;

import static com.app.security.core.constants.ErrorCode.EXPIRED_TOKEN;
import static com.app.security.core.constants.ErrorCode.INVALID_TOKEN;

@Service
@Transactional
@RequiredArgsConstructor
public class JwtTokenService {

    private final JwtProvider jwtProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    public CreateTokenResponseDto createToken(CreateTokenRequestDto requestDto) {

        String newAccessToken = jwtProvider.createAccessToken(requestDto);
        String newRefreshToken = jwtProvider.createRefreshToken(requestDto);
        LocalDateTime expireTime = jwtProvider.getExpireTime(newRefreshToken);

        refreshTokenRepository.findByUserId(requestDto.getUserId())
                .ifPresentOrElse(
                        refreshToken -> refreshToken.updateRefreshToken(newRefreshToken, expireTime),
                        () -> refreshTokenRepository.save(RefreshToken.builder()
                                .userId(requestDto.getUserId())
                                .refreshToken(newRefreshToken)
                                .expiredTime(expireTime)
                                .build())
                );

        return CreateTokenResponseDto.builder()
                .userId(requestDto.getUserId())
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build();
    }

    public RefreshTokenResponseDto refreshToken(RefreshTokenRequestDto requestDto) throws Exception {
        String refreshToken = requestDto.getRefreshToken();

        // validation Token
        jwtProvider.validateToken(refreshToken);

        // validation Claims
        Claims claims = jwtProvider.parseClaims(refreshToken);
        jwtProvider.validateClaims(claims);

        if (claims.getExpiration().before(new Date())) {
            throw new JWTException(EXPIRED_TOKEN);
        }

        Long userId = requestDto.getUserId();

        refreshTokenRepository.findByUserIdAndRefreshToken(userId, refreshToken)
                .orElseThrow(() -> new JWTException(INVALID_TOKEN));

        // ?????? ??????
        String accessToken = jwtProvider.createAccessToken(new CreateTokenRequestDto(userId));

        return RefreshTokenResponseDto.builder()
                .userId(userId)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
}
