package com.bido.auth.repository;

import com.bido.auth.entity.User;
import com.bido.auth.entity.enums.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    //SELECT * FROM users WHERE role != 'ADMIN' ORDER BY id ASC
    List<User> findByRoleNotOrderByIdAsc(UserRole role);
}
