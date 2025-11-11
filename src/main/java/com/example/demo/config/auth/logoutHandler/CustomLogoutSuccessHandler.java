package com.example.demo.config.auth.logoutHandler;

import com.example.demo.config.auth.PrincipalDetails;
import com.example.demo.config.auth.jwt.JWTProperties;
import com.example.demo.domain.repository.JwtTokenRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.Arrays;

@Slf4j
@Component
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String KAKAO_CLIENT_ID;

    @Value("${spring.security.oauth2.client.kakao.logout.redirect.uri}")
    private String KAKAO_REDIRECT_URI;

    @Autowired
    private JwtTokenRepository jwtTokenRepository;

    // 로컬서버 로그아웃 이후 추가 처리(ex. 카카오인증서버 연결해제...)
    @Override
    @Transactional(rollbackFor = Exception.class,transactionManager = "jpaTransactionManager")
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("CustomLogoutHandler's onLogoutSuccess invoke...!");

        //accessToken cookie 삭제
        String token = null;
        Cookie[] cookies = request.getCookies();
        if(cookies != null){
            token = Arrays.stream(request.getCookies())
                    .filter((cookie)->{return cookie.getName().equals(JWTProperties.ACCESS_TOKEN_COOKIE_NAME);})
                    .findFirst()
                    .map((cookie)->{return cookie.getValue();})
                    .orElse(null);
        }
        //DB 제거
        if(token!=null){
            jwtTokenRepository.deleteByAccessToken(token);
            Cookie cookie = new Cookie(JWTProperties.ACCESS_TOKEN_COOKIE_NAME,null);
            cookie.setMaxAge(0);
            response.addCookie(cookie);
        }

        //OAUTH2확인
        PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal(); //사용자 인증 정보(authentication)을 PrincipalDetails로 포장
        String provider = principalDetails.getDto().getProvider();
        System.out.println("..." + provider);
        System.out.println(principalDetails);

        if(provider!=null && provider.startsWith("Kakao"))
        {
            System.out.println(KAKAO_CLIENT_ID + "      " + KAKAO_REDIRECT_URI);
            response.sendRedirect("https://kauth.kakao.com/oauth/logout?client_id="+KAKAO_CLIENT_ID+"&logout_redirect_uri="+KAKAO_REDIRECT_URI);

            return ;
        }
        else if(provider != null && provider.startsWith("Naver")){
            response.sendRedirect("https://nid.naver.com/nidlogin.logout?returl=https://www.naver.com/");
            return ;
        }
        else if(provider != null &&provider.startsWith("Google"))
        {
            response.sendRedirect("https://accounts.google.com/Logout");
            return ;
        }

        response.sendRedirect("/");
    }
}
