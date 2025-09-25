package kr.co.logintest.web;

import kr.co.logintest.domain.User;
import kr.co.logintest.repository.UserRepository;
import kr.co.logintest.web.dto.AuthDtos;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 사용자 API: 내 정보 조회(me).
 */
@RestController
@RequestMapping("/users")
public class UserController {
    private final UserRepository users;

    public UserController(UserRepository users) {
        this.users = users;
    }

    /**
     * 현재 인증된 사용자의 프로필 반환.
     */
    @GetMapping("/me")
    public ResponseEntity<AuthDtos.UserResponse> me(Authentication authentication) {
        Long userId = Long.parseLong((String) authentication.getPrincipal());
        User u = users.findById(userId).orElseThrow();
        return ResponseEntity.ok(AuthDtos.UserResponse.builder()
                .id(u.getId())
                .email(u.getEmail())
                .name(u.getName())
                .roles(new String[]{u.getRole().name()})
                .build());
    }
}
