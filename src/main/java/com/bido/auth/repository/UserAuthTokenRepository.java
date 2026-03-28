package com.bido.auth.repository;

import com.bido.auth.entity.UserAuthToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserAuthTokenRepository extends JpaRepository<UserAuthToken, Long> {

    Optional<UserAuthToken> findByEmail(String email);
}

