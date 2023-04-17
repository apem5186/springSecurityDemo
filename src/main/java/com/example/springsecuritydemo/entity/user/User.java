package com.example.springsecuritydemo.entity.user;

import com.example.springsecuritydemo.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
@NoArgsConstructor
@Builder
@Entity
@Table(name = "users")
public class User extends BaseEntity implements UserDetails{

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, unique = true)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole userRole;

    @Column
    private boolean isLogin = false;

    public void modify(String username, String password, String email) {
        this.username = username;
        this.password = password;
        this.email = email;
    }

    public User(Long id, String username, String password, String email,
                UserRole userRole, boolean isLogin) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.email = email;
        this.userRole = userRole;
        this.isLogin = isLogin;
    }

    public static User build(User user) {
//        List<GrantedAuthority> authorities = user.getAuthorities().stream()
//                .map(role -> new SimpleGrantedAuthority(role.getAuthority()))
//                .collect(Collectors.toList());

        return new User(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.getEmail(),
                user.getUserRole(),
                user.isLogin
        );
    }

    public boolean isLogin() {
        return isLogin;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singleton(new SimpleGrantedAuthority(getUserRole().getValue()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
