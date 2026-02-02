package com.coraho.ecommerceservice.config;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;

@Component
public class RateLimitConfig {

    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();

    public enum RateLimitType {
        LOGIN(5, Duration.ofMinutes(15)), // 5 attempts per 15 munites
        FORGOT_PASSWORD(3, Duration.ofHours(1)),
        RESET_PASSWORD(5, Duration.ofMinutes(15)),
        RESEND_VERIFICATION(3, Duration.ofMinutes(30)),
        REGISTER(10, Duration.ofHours(1)),
        REFRESH_TOKEN(20, Duration.ofMinutes(5));

        private final int capacity;
        private final Duration refillDuration;

        RateLimitType(int capacity, Duration refillDuration) {
            this.capacity = capacity;
            this.refillDuration = refillDuration;
        }

        public Bandwidth getBandwidth() {
            return Bandwidth.builder()
                    .capacity(capacity)
                    .refillIntervally(capacity, refillDuration)
                    .build();
        }
    }

    public Bucket resolveBucket(String key, RateLimitType rateLimitType) {
        return cache.computeIfAbsent(key, k -> createBucket(rateLimitType));
    }

    private Bucket createBucket(RateLimitType rateLimitType) {
        return Bucket.builder()
                .addLimit(rateLimitType.getBandwidth())
                .build();
    }

}
