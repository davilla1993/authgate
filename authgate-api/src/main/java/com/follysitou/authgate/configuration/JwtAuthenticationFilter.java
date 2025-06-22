package com.follysitou.authgate.configuration;

import com.follysitou.authgate.repository.BlackListedTokenRepository;
import com.follysitou.authgate.repository.UserRepository;
import com.follysitou.authgate.service.AuthService;
import com.follysitou.authgate.service.JwtService;
import com.follysitou.authgate.utils.TokenUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final AuthService authService;
    private final UserRepository userRepository;
    private final BlackListedTokenRepository blackListedTokenRepository;

    public JwtAuthenticationFilter(JwtService jwtService,
                                   @Lazy AuthService authService,
                                   UserRepository userRepository,
                                   BlackListedTokenRepository blackListedTokenRepository) {
        this.jwtService = jwtService;
        this.authService = authService;
        this.userRepository = userRepository;
        this.blackListedTokenRepository = blackListedTokenRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response,
                                   @NonNull FilterChain filterChain) throws ServletException, IOException {

        // 1. Extraire le token du header
        log.debug("Début du filtre JWT pour : {}", request.getRequestURI());

        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Aucun token Bearer trouvé dans l'en-tête");

            filterChain.doFilter(request, response);
            return;
        }

        // 2. Vérifier la blacklist (pour les access ET refresh tokens)
        final String jwt = authHeader.substring(7);
        log.debug("Token JWT reçu : {}", jwt);

        if (!jwtService.isTokenValid(jwt)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
            return;
        }

        String tokenHash = TokenUtils.sha256(jwt);
        if (blackListedTokenRepository.existsByTokenHash(tokenHash)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid session");
            return;
        }

        try {

            // 3. Valider le token
            String userEmail = jwtService.extractUsername(jwt);
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                log.debug("Validation du token pour l'utilisateur : {}", userEmail);

                UserDetails userDetails = this.authService.loadUserByUsername(userEmail);

                if (jwtService.validateToken(jwt, userDetails)) {
                    log.debug("Token valide pour {}", userEmail);

                 //   userRepository.updateLastActivityAndOnline(userEmail, Instant.now(), true);

                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    log.info("Authenticating user with token for email: {}", userEmail);
                }
            }
        } catch(Exception ex) {
            log.error("Erreur lors de la validation du token : ", ex);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
            return;
        }
        filterChain.doFilter(request, response);
    }
}

