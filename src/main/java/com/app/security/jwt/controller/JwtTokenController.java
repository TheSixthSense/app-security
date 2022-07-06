package com.app.security.jwt.controller;

import com.app.security.jwt.dto.CreateTokenRequestDto;
import com.app.security.jwt.dto.CreateTokenResponseDto;
import com.app.security.jwt.service.JwtTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequiredArgsConstructor
public class JwtTokenController {

    private final JwtTokenService jwtTokenService;

    /**
     * JWT 발급
     */
    @PostMapping(value = "/auth")
    public ResponseEntity<CreateTokenResponseDto> createToken(@Valid @RequestBody CreateTokenRequestDto createTokenRequestDto) {
        CreateTokenResponseDto responseDto = jwtTokenService.createToken(createTokenRequestDto.getUserId());
        return ResponseEntity.ok().body(responseDto);
    }

}
