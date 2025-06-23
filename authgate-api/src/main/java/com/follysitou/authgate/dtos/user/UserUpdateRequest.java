package com.follysitou.authgate.dtos.user;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserUpdateRequest {

    @NotBlank(message = "First name is required")
    @Size(min = 2, max = 20)
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Size(min = 2, max = 20)
    private String lastName;

    private String email;

}
