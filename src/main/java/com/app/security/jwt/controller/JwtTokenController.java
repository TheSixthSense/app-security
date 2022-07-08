package com.app.security.jwt.controller;

import com.app.security.core.response.RestResponse;
import com.app.security.jwt.dto.CreateTokenRequestDto;
import com.app.security.jwt.dto.CreateTokenResponseDto;
import com.app.security.jwt.service.JwtTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
public class JwtTokenController {

    private final JwtTokenService jwtTokenService;

    /**
     * JWT 발급
     */
    @PostMapping(value = "/auth")
    public RestResponse<CreateTokenResponseDto> createToken(@Valid @RequestBody CreateTokenRequestDto createTokenRequestDto) {
        CreateTokenResponseDto responseDto = jwtTokenService.createToken(createTokenRequestDto.getUserId());
        return RestResponse
                .withData(responseDto)
                .withUserMessageKey("success.auth.token.create")
                .build();
    }

}