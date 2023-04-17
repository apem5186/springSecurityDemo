package com.example.springsecuritydemo.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserModifyDTO {

    @NotEmpty(message = "userId는 필수입니다.")
    private Long userId;

    @NotEmpty(message = "username은 필수입니다.")
    private String username;

    @NotEmpty(message = "email은 필수입니다.")
    @Email
    private String email;

    @NotEmpty(message = "password는 필수입니다.")
    private String password;
}
