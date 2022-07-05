package com.app.security.controller;

import com.app.security.dto.CreateTokenRequestDto;
import com.app.security.dto.CreateTokenResponseDto;
import com.app.security.service.JwtTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class JwtTokenController {

    private final JwtTokenService jwtTokenService;

    /**
     * JWT 발급
     */
    @PostMapping(value = "/create/token")
    public ResponseEntity<CreateTokenResponseDto> createToken(@RequestBody CreateTokenRequestDto createTokenRequestDto) {
        CreateTokenResponseDto responseDto = jwtTokenService.createToken(createTokenRequestDto.getUserId());
        return ResponseEntity.ok().body(responseDto);
    }

}
