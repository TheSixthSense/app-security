package com.app.security.core.auth;

import com.app.security.jwt.domain.enumType.Role;
import com.app.security.jwt.dto.ValidateTokenResponseDto;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.*;

@Slf4j
@Component
public class JwtProvider {
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.issuer}")
    private String jwtIssuer;

    @Value("${jwt.expireTime}")
    private long jwtExpireTime;

    public SecretKey getJwtSecret() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String createToken(long userId, Role role) {
        return Jwts.builder()
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
                .setIssuedAt(new Date())
                .setIssuer(jwtIssuer)
                .claim("user_id", userId)
                .claim("role", role)
                .signWith(getJwtSecret(), SignatureAlgorithm.HS256)
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpireTime))
                .compact();
    }

    public ValidateTokenResponseDto getTokenInfo(String token) {
        Claims claims = parseClaims(token);

        return ValidateTokenResponseDto.builder()
                .userId(claims.get("user_id", Long.class))
                .role(claims.get("role").toString())
                .issuedAt(claims.getIssuedAt())
                .expiredAt(claims.getExpiration())
                .build();
    }

    public Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getJwtSecret())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Authentication getAuthentication(String accessToken) {
        Claims claims = parseClaims(accessToken);
        validateClaims(claims);

        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority(claims.get("role").toString()));

        UserDetails principal = new User(claims.get("user_id").toString(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    public void validateClaims(Claims claims) {
        if (Objects.isNull(claims)) {
            log.error("[JWT Token Filter Error]: claims User Not Found. Please check header.");
        }
        if (Objects.isNull(claims.get("role"))) {
            log.error("[JWT Token Filter Error]: User Not Found. Please check header.");
        }
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getJwtSecret())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}
