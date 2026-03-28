package com.bido.auth.repository;

import com.bido.auth.entity.LoginRateLimit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface LoginRateLimitRepository extends JpaRepository<LoginRateLimit, String> {
}

