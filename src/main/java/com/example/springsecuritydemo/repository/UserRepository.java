package com.example.springsecuritydemo.repository;

import com.example.springsecuritydemo.entity.user.User;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    @Transactional
    @Modifying
    @Query("UPDATE User s SET  s.password =:pw WHERE s.id =:id")
    void updateUserPassword(int id, String pw);

    @Query("SELECT u FROM User u WHERE u.isLogin = true")
    List<User> findUserByIsLogin();
}
