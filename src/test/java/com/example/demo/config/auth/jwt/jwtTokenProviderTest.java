//package com.example.demo.config.auth.jwt;
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.JwtParser;
//import io.jsonwebtoken.Jwts;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//
//import java.security.Key;
//
//import static org.junit.jupiter.api.Assertions.*;
//
//@SpringBootTest
//class jwtTokenProviderTest {
//
//    @Autowired
//    private jwtTokenProvider tokenProvider;
//
//    @Test
//    public void t1() throws Exception{
//        TokenInfo tokenInfo = tokenProvider.GenerateToken();
//        System.out.println(tokenInfo);
//
//        //복호화
//        Key key = tokenProvider.getKey();
//        JwtParser parser = Jwts.parser()
//                .setSigningKey(key)
//                .build();
//        //엑세스 토큰 가져오기
//        String accessToken = tokenInfo.getAccessToken();
//        Claims claims = parser.parseClaimsJws(accessToken).getBody();
//        //get
//        String username = claims.get("username").toString();
//        String role = claims.get("role").toString();
//        //출력
//        System.out.println("username : " + username);
//        System.out.println("role : " + role);
//    }
//    @Test
//    public void t2() throws Exception{
//
//    }
//
//}