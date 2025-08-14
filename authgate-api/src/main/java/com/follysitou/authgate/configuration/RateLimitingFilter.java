package com.follysitou.authgate.configuration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.bucket4j.*;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.*;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class RateLimitingFilter implements Filter {

    @Value("${rate-limiting.max-failed-attempts}")
    private int maxAttempts;

    @Value("${rate-limiting.refill-duration-minutes}")
    private long refillMinutes;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, Bucket> limitMap = new ConcurrentHashMap<>();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String path = httpRequest.getRequestURI();

        if (path.startsWith("/swagger-ui") || path.startsWith("/v3/api-docs") || path.startsWith("/swagger-resources")) {
            chain.doFilter(request, response);
            return;
        }

        if (path.startsWith("/auth/register")) {
            CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(httpRequest);

            String clientIp = getClientIP(cachedRequest);
            String email = extractEmailFromBody(cachedRequest);

            String rateLimitKey = clientIp + ":" + (email != null ? email.toLowerCase() : "unknown");

            Bucket bucket = limitMap.computeIfAbsent(rateLimitKey, key -> Bucket.builder()
                    .addLimit(Bandwidth.classic(
                            maxAttempts,
                            Refill.greedy(maxAttempts, Duration.ofMinutes(refillMinutes))
                    )).build());

            ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

            if (!probe.isConsumed()) {
                log.warn("Rate limiting triggered for IP/email: {}", rateLimitKey);
                httpResponse.setContentType("application/json");
                httpResponse.setStatus(429);
                httpResponse.getWriter().write("""
                    {
                      "success": false,
                      "message": "Too many registration attempts from your device or network. Please try again later."
                    }
                    """);
                return;
            }

            chain.doFilter(cachedRequest, response);
        } else {
            chain.doFilter(request, response);
        }
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        return xfHeader != null ? xfHeader.split(",")[0] : request.getRemoteAddr();
    }

    private String extractEmailFromBody(HttpServletRequest request) {
        try {
            String body = new BufferedReader(new InputStreamReader(request.getInputStream()))
                    .lines()
                    .reduce("", (acc, line) -> acc + line);

            JsonNode jsonNode = objectMapper.readTree(body);
            if (jsonNode.has("email")) {
                return jsonNode.get("email").asText();
            }
        } catch (IOException e) {
            log.error("Failed to parse request body to extract email", e);
        }
        return null;
    }
}
