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
    private final BlackListedTokenRepository blackListedTokenRepository;

    public JwtAuthenticationFilter(JwtService jwtService,
                                   @Lazy AuthService authService,
                                   BlackListedTokenRepository blackListedTokenRepository) {
        this.jwtService = jwtService;
        this.authService = authService;
        this.blackListedTokenRepository = blackListedTokenRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String requestUri = request.getRequestURI();
        log.debug("➡️ Début du filtre JWT - URI: {} - Méthode: {}", requestUri, request.getMethod());

        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("⚠️ Aucun token Bearer trouvé dans l'en-tête pour {}", requestUri);
            filterChain.doFilter(request, response);
            return;
        }

        // Extraction du token
        final String jwt = authHeader.substring(7);
        log.debug("🔑 Token JWT reçu: {}", jwt);

        // Vérification basique de validité
        if (!jwtService.isTokenValid(jwt)) {
            log.error("⛔ Token invalide (signature/expiration) pour {}", requestUri);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
            return;
        }

        // Vérification de la blacklist
        String tokenHash = TokenUtils.sha256(jwt);
        if (blackListedTokenRepository.existsByTokenHash(tokenHash)) {
            log.error("⛔ Token blacklisté pour {}", requestUri);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid session");
            return;
        }

        try {
            String userEmail = jwtService.extractUsername(jwt);
            log.debug("📧 Utilisateur extrait du token: {}", userEmail);

            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.authService.loadUserByUsername(userEmail);

                log.debug("✅ Utilisateur chargé depuis AuthService : {}", userDetails.getUsername());
                log.debug("📜 Authorities de l'utilisateur: {}", userDetails.getAuthorities());

                if (jwtService.validateToken(jwt, userDetails)) {
                    log.info("🔓 Token valide - authentification établie pour {}", userEmail);

                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);

                } else {
                    log.error("⛔ Token non valide après validation complète pour {}", userEmail);
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
                    return;
                }
            }
        } catch (Exception ex) {
            log.error("💥 Erreur lors de la validation du token: ", ex);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
            return;
        }

        // Poursuite de la chaîne de filtres
        log.debug("➡️ Fin du filtre JWT - Passage au contrôleur");
        filterChain.doFilter(request, response);
    }
}


