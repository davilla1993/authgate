package com.follysitou.authgate.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collections;


@Component
@Slf4j
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException exception) throws IOException {

        // Log détaillé de l'erreur
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.error("🔴 Access denied - URL: {} - Method: {} - User: {} - Roles: {}",
                request.getRequestURI(),
                request.getMethod(),
                (auth != null) ? auth.getName() : "anonymous",
                (auth != null) ? auth.getAuthorities() : Collections.emptyList());

        // Construction de la réponse cohérente avec RestExceptionHandler
        String message = (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken))
                ? "You do not have the necessary permissions to access this resource."
                : "Authentication required to access this resource";

        ErrorDto errorDto = ErrorDto.builder()
                .code(ErrorCodes.FORBIDDEN_ACCESS)
                .httpCode(HttpStatus.FORBIDDEN.value())
                .message(message)
                .errors(Collections.singletonList(exception.getMessage()))
                .build();

        // Sérialisation de la réponse
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.getWriter().write(new ObjectMapper().writeValueAsString(errorDto));
    }
}

