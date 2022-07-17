package com.app.security.jwt.entity;

import com.app.security.common.entity.BaseTimeEntity;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Getter
@NoArgsConstructor
@Table(name = "refresh_token")
public class RefreshToken extends BaseTimeEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private Long userId;

    @Column(nullable = false)
    private String refreshToken;

    @Column(nullable = false)
    private LocalDateTime expiredTime;

    @Builder
    public RefreshToken(Long id, Long userId, String refreshToken, LocalDateTime expiredTime) {
        this.id = id;
        this.userId = userId;
        this.refreshToken = refreshToken;
        this.expiredTime = expiredTime;
    }

    public RefreshToken updateRefreshToken(String token, LocalDateTime expiredTime) {
        return RefreshToken.builder()
                .id(this.id)
                .userId(this.userId)
                .refreshToken(token)
                .expiredTime(expiredTime)
                .build();
    }
}
