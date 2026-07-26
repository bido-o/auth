package com.bido.auth.service;

import com.bido.auth.entity.User;
import com.bido.auth.exception.UserNotFoundException;
import com.bido.auth.repository.RefreshTokenRepository;
import com.bido.auth.repository.UserRepository;
import com.bido.auth.utils.ErrorMessages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;

/**
 * Suspendarea/reactivarea unui cont.
 *
 * Suspendarea acționează pe trei niveluri, pentru revocare completă:
 *  1. DB (isSuspended) — sursa de adevăr, blochează login + refresh permanent;
 *  2. refresh-urile din DB sunt șterse — userul nu-și mai poate reînnoi tokenul;
 *  3. denylist Redis (TTL = durata access token-ului) — gateway-ul respinge instant
 *     access token-ul încă viu, fără să aștepte expirarea lui.
 */
@Service
public class SuspensionService {

    private static final Logger log = LoggerFactory.getLogger(SuspensionService.class);

    private static final String DENYLIST_KEY_PREFIX = "suspended:";

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final StringRedisTemplate redis;
    private final Duration denylistTtl;

    public SuspensionService(UserRepository userRepository,
                             RefreshTokenRepository refreshTokenRepository,
                             StringRedisTemplate redis,
                             @Value("${jwt.access-token.expiration}") long accessTokenExpirationMs) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.redis = redis;
        // După expirarea access token-ului, gateway-ul îl respinge oricum pe exp,
        // deci intrarea din denylist nu trebuie să trăiască mai mult.
        this.denylistTtl = Duration.ofMillis(accessTokenExpirationMs);
    }

    @Transactional
    public void suspend(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(ErrorMessages.USER_NOT_FOUND));

        user.setSuspended(true);
        userRepository.save(user);

        // Nu-și mai poate lua token nou (blocare permanentă).
        refreshTokenRepository.deleteByUser(user);

        // Revocare instant a access token-ului viu la gateway.
        redis.opsForValue().set(DENYLIST_KEY_PREFIX + userId, "1", denylistTtl);

        log.info("User {} suspendat: DB + refresh-uri șterse + denylist Redis (TTL {}).", userId, denylistTtl);
    }

    @Transactional
    public void unsuspend(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(ErrorMessages.USER_NOT_FOUND));

        user.setSuspended(false);
        userRepository.save(user);

        redis.delete(DENYLIST_KEY_PREFIX + userId);

        log.info("User {} reactivat: DB + denylist Redis curățat.", userId);
    }
}
