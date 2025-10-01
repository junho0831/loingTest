package kr.co.logintest.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;

/**
 * Refresh 토큰 메타데이터 저장 엔티티.
 * - HttpOnly 쿠키로 전달된 JWT의 jti를 서버 측에 저장해 재사용/무효화 여부를 추적
 * - 개별 로그아웃 시 단일 레코드만 폐기, 전체 로그아웃 시 사용자 전체 레코드를 일괄 비활성화
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "refresh_tokens", indexes = {
        @Index(name = "idx_refresh_tokens_jti", columnList = "jti", unique = true),
        @Index(name = "idx_refresh_tokens_user", columnList = "user_id")
})
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "jti", nullable = false, length = 64, unique = true)
    private String jti;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked", nullable = false)
    private boolean revoked;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Instant updatedAt;

    public boolean isExpired(Instant now) {
        return expiresAt.isBefore(now);
    }

    public void revoke(Instant when) {
        if (!revoked) {
            this.revoked = true;
            this.revokedAt = when;
        }
    }
}
