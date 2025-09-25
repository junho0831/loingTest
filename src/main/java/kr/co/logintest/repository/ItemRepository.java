package kr.co.logintest.repository;

import kr.co.logintest.domain.Item;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ItemRepository extends JpaRepository<Item, Long> {}

