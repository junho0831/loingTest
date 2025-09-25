package kr.co.logintest.web;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import kr.co.logintest.domain.Item;
import kr.co.logintest.repository.ItemRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 공개/보호 리소스 예시: 아이템 목록(공개), 생성(ROLE_USER 필요).
 */
@RestController
@Validated
public class ItemController {
    private final ItemRepository items;

    public ItemController(ItemRepository items) {
        this.items = items;
    }

    @GetMapping("/items")
    public List<Item> list() {
        return items.findAll();
    }

    public record CreateItemRequest(@NotBlank String name) {}

    @PostMapping("/items")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> create(@Valid @RequestBody CreateItemRequest req) {
        Item item = Item.builder().name(req.name()).build();
        item = items.save(item);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "id", item.getId(),
                "name", item.getName()
        ));
    }
}
