package com.app.security.controller;

import com.app.security.EnumType.ROLE;
import com.app.security.auth.JwtProvider;
import com.app.security.dto.CreateTokenRequestDto;
import com.app.security.dto.CreateTokenResponseDto;
import com.app.security.dto.ValidateTokenResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class JwtTokenController {

    private final JwtProvider jwtProvider;

    /**
     * JWT 발급
     */
    @PostMapping(value = "/create/token")
    public ResponseEntity<CreateTokenResponseDto> createToken(@RequestBody CreateTokenRequestDto createTokenRequestDto) throws Exception {
        // TODO : DB select, service로 빼기
        ROLE role = ROLE.USER;
        String token = jwtProvider.createToken(createTokenRequestDto.getUserId(), role);
        CreateTokenResponseDto createTokenResponseDto = new CreateTokenResponseDto(createTokenRequestDto.getUserId(), token);

        return ResponseEntity.ok().body(createTokenResponseDto);
    }

}
