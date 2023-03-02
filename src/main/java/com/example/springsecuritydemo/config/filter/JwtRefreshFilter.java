package com.example.springsecuritydemo.config.filter;

import com.example.springsecuritydemo.service.jwt.AccessTokenResponse;
import com.example.springsecuritydemo.service.jwt.TokenProvider;
import com.example.springsecuritydemo.service.user.UserSecurityService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class JwtRefreshFilter extends OncePerRequestFilter {

    private final TokenProvider tokenProvider;
    private final UserSecurityService userSecurityService;

    public JwtRefreshFilter(TokenProvider tokenProvider, UserSecurityService userSecurityService) {
        this.tokenProvider = tokenProvider;
        this.userSecurityService = userSecurityService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String refreshJwt = getRefreshJwtFromRequest(request);

            if (StringUtils.hasText(refreshJwt) && tokenProvider.validateToken(refreshJwt)) {
                Long userId = tokenProvider.getUserIdFromToken(refreshJwt);
                UserDetails userDetails = userSecurityService.loadUserById(userId);

                if (userDetails != null) {
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }

                AccessTokenResponse accessTokenResponse = tokenProvider.generateToken((Authentication) userDetails);

                String newAccessToken = accessTokenResponse.getAccessToken();
                String newRefreshToken = accessTokenResponse.getRefreshToken();

                log.info("Access Token : " + newAccessToken);
                log.info("Refresh Token : " + newRefreshToken);

                response.getWriter().write(new ObjectMapper().writeValueAsString(accessTokenResponse));
                response.setContentType("application/json");
            }
        } catch (Exception ex) {
            logger.error("Could not refresh access token", ex);
        }

        filterChain.doFilter(request, response);
    }

    private String getRefreshJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Refresh ")) {
            return bearerToken.substring(8);
        }
        return null;
    }
}

