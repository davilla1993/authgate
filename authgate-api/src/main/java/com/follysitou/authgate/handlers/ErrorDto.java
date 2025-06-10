package com.follysitou.authgate.handlers;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ErrorDto {

    private ErrorCodes code;

    private Integer httpCode;

    private String message;

    private List<String> errors = new ArrayList<>();
}
