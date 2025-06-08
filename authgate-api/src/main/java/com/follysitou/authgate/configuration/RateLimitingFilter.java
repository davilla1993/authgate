package com.follysitou.authgate.configuration;

import io.github.bucket4j.*;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;

@Slf4j
@Component
public class RateLimitingFilter implements Filter {

    private final Bucket loginBucket = Bucket.builder()
            .addLimit(Bandwidth.classic(10, Refill.greedy(10, Duration.ofMinutes(1))))
            .build();

    // Limite standard pour les autres endpoints
    private final Bucket defaultBucket = Bucket.builder()
            .addLimit(Bandwidth.classic(5, Refill.greedy(5, Duration.ofMinutes(1))))
            .build();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String path = httpRequest.getRequestURI();
        Bucket targetBucket = path.startsWith("/api/auth/login") ? loginBucket : defaultBucket;

        ConsumptionProbe probe = targetBucket.tryConsumeAndReturnRemaining(1);

        if (!probe.isConsumed()) {
            log.warn("Rate limiting triggered for IP: {}", request.getRemoteAddr());
            ((HttpServletResponse)response).setContentType("application/json");
            ((HttpServletResponse)response).setStatus(429);
            response.getWriter().write("{\"success\":false, \"message\":\"Too many attempts. Please try again later. Thank you.\"}");
            return;
        }
        chain.doFilter(request, response);
    }
}
