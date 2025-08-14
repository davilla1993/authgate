package com.follysitou.authgate.controllers;

import com.follysitou.authgate.dtos.auth.*;
import com.follysitou.authgate.exceptions.UnauthorizedException;
import com.follysitou.authgate.handlers.ErrorCodes;
import com.follysitou.authgate.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

@RestController
@Slf4j
@RequestMapping("/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse> register(@Valid @RequestBody RegisterRequest registerRequest) {

        ApiResponse response = authService.register(registerRequest);

        if (response.isSuccess()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            AuthResponse response = authService.login(loginRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Connection error : " + e.getMessage()));
        }
    }

    @PostMapping("/verify-registration")
    public ResponseEntity<?> verifyRegistration(@Valid @RequestBody VerificationRequest verificationRequest) {
        try {
            AuthResponse response = authService.verifyRegistrationCode(verificationRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Verification error : " + e.getMessage()));
        }
    }


    @PostMapping("/verify-login")
    public ResponseEntity<?> verifyLogin(@Valid @RequestBody VerificationRequest verificationRequest) {
        try {
            AuthResponse response = authService.verifyLoginCode(verificationRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Verification error : " + e.getMessage()));
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest forgotPasswordRequest) {
        try {
            ApiResponse response = authService.forgotPassword(forgotPasswordRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Error : " + e.getMessage()));
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {
        try {
            ApiResponse response = authService.resetPassword(resetPasswordRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(new ApiResponse(false, "Error : " + e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response,
            @CookieValue(name = "refreshToken", required = false) String refreshToken,
            @RequestHeader(name = "X-XSRF-TOKEN", required = false) String csrfHeader,
            @CookieValue(name = "XSRF-TOKEN", required = false) String csrfCookie
    ) {
        ApiResponse apiResponse = authService.logout(
                request,
                response,
                refreshToken,
                csrfHeader,
                csrfCookie
        );

        return apiResponse.isSuccess()
                ? ResponseEntity.ok(apiResponse)
                : ResponseEntity.status(apiResponse.getMessage().contains("CSRF")
                        ? HttpStatus.FORBIDDEN
                        : HttpStatus.BAD_REQUEST)
                .body(response);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<AuthResponse> refreshToken(
            @CookieValue(name = "refreshToken", required = false) String cookieRefreshToken,
            @RequestBody(required = false) Map<String, String> requestBody,
            HttpServletResponse response) {

        String refreshToken = Optional.ofNullable(cookieRefreshToken)
                .or(() -> Optional.ofNullable(requestBody).map(body -> body.get("refreshToken")))
                .orElseThrow(() -> new UnauthorizedException("Refresh token is required", ErrorCodes.TOKEN_INVALID));

        try {
            AuthResponse authResponse = authService.refreshToken(refreshToken, response);
            return ResponseEntity.ok(authResponse);
        } catch (UnauthorizedException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthResponse(e.getMessage(), false));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthResponse("Internal server error", false));
        }
    }

    @GetMapping("/now")
    public String now() {
        return Instant.now().toString();
    }
}
