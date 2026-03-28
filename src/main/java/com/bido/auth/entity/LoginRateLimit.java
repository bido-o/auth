package com.bido.auth.entity;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "login_rate_limits")
public class LoginRateLimit {

    @Id
    private String email;

    @Column(nullable = false)
    private int tokensRequested = 0;

    private Instant blockedUntil;

    @Column(nullable = false)
    private Instant lastAttemptAt = Instant.now();

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public int getTokensRequested() {
        return tokensRequested;
    }

    public void setTokensRequested(int tokensRequested) {
        this.tokensRequested = tokensRequested;
    }

    public Instant getBlockedUntil() {
        return blockedUntil;
    }

    public void setBlockedUntil(Instant blockedUntil) {
        this.blockedUntil = blockedUntil;
    }

    public Instant getLastAttemptAt() {
        return lastAttemptAt;
    }

    public void setLastAttemptAt(Instant lastAttemptAt) {
        this.lastAttemptAt = lastAttemptAt;
    }
}
