package com.example.springsecuritydemo.service.user;

import com.example.springsecuritydemo.entity.user.User;
import com.example.springsecuritydemo.entity.user.UserRole;
import com.example.springsecuritydemo.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    @Transactional
    public void signUp(String username, String email, String password) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setUserRole(UserRole.USER);
        userRepository.save(user);
    }

    @Transactional
    public void adminSignUp(String username, String email, String password) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setUserRole(UserRole.ADMIN);
        userRepository.save(user);
    }
}
