package com.follysitou.authgate.dtos.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LockAccountRequest {

    @NotBlank
    @Email
    private String email;

    @NotBlank
    @Size(min = 10, max = 500)
    private String reason;
}
