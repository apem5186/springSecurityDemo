package com.example.springsecuritydemo.config;

import com.example.springsecuritydemo.config.filter.JwtAuthenticationFilter;
import com.example.springsecuritydemo.config.filter.JwtRefreshFilter;
import com.example.springsecuritydemo.config.handler.CustomAuthenticationFailureHandler;
import com.example.springsecuritydemo.service.jwt.TokenProvider;
import com.example.springsecuritydemo.service.user.UserSecurityService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web -> web.ignoring().requestMatchers("/h2-console/**"));
    }
    private final UserSecurityService userSecurityService;

    private final TokenProvider tokenProvider;
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http.authorizeHttpRequests()
                .requestMatchers(new AntPathRequestMatcher("/login")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/signUp")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/h2-console")).permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(new JwtAuthenticationFilter(tokenProvider, userSecurityService), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtRefreshFilter(tokenProvider, userSecurityService), JwtAuthenticationFilter.class)
                .csrf().ignoringRequestMatchers(
                        new AntPathRequestMatcher("/h2-console/**"))
                .and()
                .headers()
                .addHeaderWriter(new XFrameOptionsHeaderWriter(
                        XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN
                ))
                .and()
                .formLogin()
                .loginPage("/login")
                .defaultSuccessUrl("/")
                .failureHandler(new CustomAuthenticationFailureHandler())
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new Http403ForbiddenEntryPoint())
                .and()
                .logout()
                .and().build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws
        Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
