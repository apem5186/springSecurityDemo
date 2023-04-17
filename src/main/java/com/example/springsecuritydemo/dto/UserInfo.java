package com.example.springsecuritydemo.dto;

import com.example.springsecuritydemo.entity.user.UserRole;
import lombok.Getter;

@Getter
public class UserInfo {

    private Long userId;

    private String username;

    private String email;

    private String password;

    private UserRole userRole;

    private boolean isLogin;
}
