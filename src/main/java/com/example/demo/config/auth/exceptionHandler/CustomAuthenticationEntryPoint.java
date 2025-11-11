package com.example.demo.config.auth.exceptionHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override  //인증이 필요할때 ,인증이 안되어있을때 나오는 페이지 리다이렉트
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        log.error("CustomauthenticationEntryPoint's commence invoke...!");
        //로그인 페이지 및 메세지 전달
        response.sendRedirect("/login?error=" + authException.getMessage());

    }
}
