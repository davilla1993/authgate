package com.follysitou.authgate.dtos;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class RoleRequest {

    @NotBlank
    private String name;

    private Set<Long> permissionIds;
}
