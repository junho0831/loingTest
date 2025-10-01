package kr.co.logintest.repository;

import kr.co.logintest.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByJti(String jti);

    @Modifying(clearAutomatically = true)
    @Query("update RefreshToken rt set rt.revoked = true, rt.revokedAt = :now where rt.user.id = :userId and rt.revoked = false")
    int revokeAllByUserId(@Param("userId") Long userId, @Param("now") Instant now);

    @Modifying(clearAutomatically = true)
    @Query("delete from RefreshToken rt where rt.user.id = :userId")
    int deleteAllByUserId(@Param("userId") Long userId);
}
