package com.example.demo.config.auth.loginHandler;

import com.example.demo.config.auth.PrincipalDetails;
import com.example.demo.config.auth.jwt.JWTProperties;
import com.example.demo.config.auth.jwt.TokenInfo;
import com.example.demo.config.auth.jwt.JWTTokenProvider;
import com.example.demo.domain.entity.JwtToken;
import com.example.demo.domain.repository.JwtTokenRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;

@Slf4j
@Component
public class CustomSuccessHandler implements AuthenticationSuccessHandler {
    @Autowired
    JWTTokenProvider jwtTokenProvider;

    @Autowired
    JwtTokenRepository jwtTokenRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {


        //로그인 후 쿠키 발급 //7
        TokenInfo tokenInfo = jwtTokenProvider.GenerateToken(authentication);
        log.info("CustomSuccessHandler's onAuthenticationSuccess invoke...!" + tokenInfo);
        Cookie cookie = new Cookie(JWTProperties.ACCESS_TOKEN_COOKIE_NAME,tokenInfo.getAccessToken());
        cookie.setMaxAge(JWTProperties.ACCESS_TOKEN_EXPIRATION_TIME); //accesstoken 유지 시간 지정
        cookie.setPath("/"); // 쿠키 적용경로(/ : 모든 경로)
        response.addCookie(cookie); //응답정보에 쿠키 포함

        PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
        String auth = principalDetails.getDto().getRole();
        //TOKEN을 DB로 저장
        JwtToken tokenEntity = JwtToken.builder()
                                        .accessToken(tokenInfo.getAccessToken())
                                        .refreshToken(tokenInfo.getRefreshToken())
                                        .username(authentication.getName())
                                        .auth(auth)
                                        .createAt(LocalDateTime.now())
                                        .build();
        jwtTokenRepository.save(tokenEntity);



        log.info("CustomSuccessHandler's onAuthenticationSuccess invoke..getToken" + tokenInfo);

        //Role 별로 redirect 경로 수정     //로그인 이후 이동페이지 선정
        String redicectUrl = "/";

//        for(GrantedAuthority authority : authentication.getAuthorities()){
//            log.info("authourity" + authority);
//            String role = authority.getAuthority();
//
//
//            if(role.contains("ROLE_ADMIN")){
//                redicectUrl="/admin";
//                break;
//            }
//            else  if(role.contains("ROLE_MANAGER")){
//                redicectUrl="/manager";
//                break;
//            }
//            else {
//                redicectUrl="/user";
//                break;
//            }
//        }
        response.sendRedirect(redicectUrl);


    }
}
