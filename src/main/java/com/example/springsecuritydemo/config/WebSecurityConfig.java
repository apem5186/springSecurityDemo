package com.example.springsecuritydemo.config;

import com.example.springsecuritydemo.config.filter.JwtAuthenticationFilter;
import com.example.springsecuritydemo.config.filter.JwtRefreshFilter;
import com.example.springsecuritydemo.config.filter.LogoutPreProcessingFilter;
import com.example.springsecuritydemo.config.handler.CustomAuthenticationFailureHandler;
import com.example.springsecuritydemo.config.handler.CustomAuthenticationSuccessHandler;
import com.example.springsecuritydemo.config.handler.CustomLogoutHandler;
import com.example.springsecuritydemo.config.handler.CustomLogoutSuccessHandler;
import com.example.springsecuritydemo.repository.RefreshTokenRepository;
import com.example.springsecuritydemo.repository.UserRepository;
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
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web -> web.ignoring().requestMatchers("/h2-console/**", "/favicon.ico"));
    }
    private final UserSecurityService userSecurityService;

    private final RefreshTokenRepository refreshTokenRepository;

    private final UserRepository userRepository;

    @Bean
    public TokenProvider tokenProvider() {
        return new TokenProvider(refreshTokenRepository);
    }

    @Bean
    public CustomLogoutSuccessHandler customLogoutSuccessHandler() {
        return new CustomLogoutSuccessHandler(refreshTokenRepository, userRepository);
    }

    @Bean
    public CustomLogoutHandler customLogoutHandler() {
        return new CustomLogoutHandler();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        LogoutPreProcessingFilter logoutPreProcessingFilter = new LogoutPreProcessingFilter("/logout");
        return http
                .addFilterAfter(new SecurityContextPersistenceFilter(new HttpSessionSecurityContextRepository()), HeaderWriterFilter.class)
                .authorizeHttpRequests()
                .requestMatchers(new AntPathRequestMatcher("/login")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/signUp")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/h2-console")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/h2-console/**")).permitAll()
                .anyRequest().authenticated()
                .and()
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
                .successHandler(new CustomAuthenticationSuccessHandler(tokenProvider()))
                .failureHandler(new CustomAuthenticationFailureHandler())
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new Http403ForbiddenEntryPoint())
                .and()
                .addFilterBefore(new SecurityContextHolderFilter(new HttpSessionSecurityContextRepository()), LogoutFilter.class)
                .addFilterBefore(logoutPreProcessingFilter, LogoutFilter.class)
                .addFilterBefore(new JwtAuthenticationFilter(tokenProvider(), userSecurityService), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtRefreshFilter(tokenProvider(), userSecurityService), JwtAuthenticationFilter.class)
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler(customLogoutHandler())
                .addLogoutHandler(new SecurityContextLogoutHandler())
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "accessToken")
                .logoutSuccessHandler(customLogoutSuccessHandler())
                .and()
                .build();
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
