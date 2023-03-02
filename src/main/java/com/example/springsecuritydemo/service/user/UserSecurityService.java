package com.example.springsecuritydemo.service.user;

import com.example.springsecuritydemo.entity.user.User;
import com.example.springsecuritydemo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserSecurityService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("User not found with username : " + username));
        log.info("USER : " + user.getUsername() + " AND " + user.getPassword());
        return User.build(user);
    }

    public UserDetails loadUserById(Long id) throws UsernameNotFoundException {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + id));
        log.info("USER ID : " + user.getId() + " AND " + user.getPassword());
        return User.build(user);
    }

}
