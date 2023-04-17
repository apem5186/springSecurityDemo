package com.example.springsecuritydemo.service.user;

import com.example.springsecuritydemo.entity.user.User;
import com.example.springsecuritydemo.entity.user.UserRole;
import com.example.springsecuritydemo.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

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

    @Transactional
    public List<User> userList() {
        return userRepository.findAll();
    }

    @Transactional
    public void deleteUser(Long userId) {
        userRepository.deleteById(userId);
    }

    @Transactional
    public void modifyUser(Long userId, String username, String password, String email) {
        User user = userRepository.findById(userId).orElseThrow();
        user.modify(username, passwordEncoder.encode(password), email);
        userRepository.save(user);
    }

    public List<User> getConnectedUser() {
        return userRepository.findUserByIsLogin();
    }
}
