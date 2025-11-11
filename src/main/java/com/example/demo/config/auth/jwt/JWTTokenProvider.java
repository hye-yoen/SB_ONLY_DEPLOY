package com.example.demo.config.auth.jwt;

import com.example.demo.config.auth.PrincipalDetails;
import com.example.demo.domain.dtos.UserDto;
import com.example.demo.domain.entity.Signature;
import com.example.demo.domain.entity.User;
import com.example.demo.domain.repository.SignatureRepository;
import com.example.demo.domain.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component //다른 위치 주입 가능
public class JWTTokenProvider {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SignatureRepository signatureRepository;

    //Key
    private Key key;

    public Key getKey(){
        return key;
    }

    @PostConstruct // 생성자가 생성된 이후
    public void init(){
        //로그인 상태 유지
        List<Signature> list = signatureRepository.findAll();
        if(list.isEmpty()){
            //keyBytes, key, signature 생성
            byte[] keyBytes = KeyGenerator.keygen();
            this.key = Keys.hmacShaKeyFor(keyBytes);

            Signature signature = new Signature();
            signature.setKeyBytes(keyBytes);
            signature.setCreateAt(LocalDate.now());
            signatureRepository.save(signature);
        }else{
            Signature signature = list.get(0);
            this.key = Keys.hmacShaKeyFor(signature.getKeyBytes());
        }

    }

    //로그인 성공했을때 로그인 정보를 꺼내서 액세스 리프레쉬 토큰 생성, 토큰 인포로 반환
    public TokenInfo GenerateToken(Authentication authentication){

        //계정정보 - 계정명 / auth(role)
        String authorities = authentication.getAuthorities() //Collection<SimpleGrantedAuthority> authority 반환
                .stream() // Stream 함수 사용 예정
                .map((role)->{return role.getAuthority(); } ) //각각 GrantedAuthory("Role")들을 문자열 값으로 반환해서 map처리
                .collect(Collectors.joining(",")); //각각의  role(ROLE_ADMIN ROLE_USER) 를 ','를 기준으로 묶음 ("ROLE_ADMIN","ROLE_USER")
                // 문자열화 시키기

        //AccessToken(서버의 서비스를 이용제한)
        long now = (new Date()).getTime(); //현재시간
        String accessToken = Jwts.builder()
                    .setSubject(authentication.getName()) //본문 TITLE
                    .setExpiration(new Date(now + JWTProperties.ACCESS_TOKEN_EXPIRATION_TIME ) ) //만료날짜(초단위)
                    .signWith(key , SignatureAlgorithm.HS256) // 서명값
                    .claim("username",authentication.getName()) //본문내용
                    .claim("auth",authorities) // 본문내용
                    .compact();

        //RefreshToken(AccessToken 만료시 갱신처리)
        String refreshToken = Jwts.builder()
                    .setSubject("Refresh_Token_Title") //본문 TITLE
                    .setExpiration(new Date(now + JWTProperties.REFRESH_TOKEN_EXPIRATION_TIME ) ) //만료날짜(초단위)
                    .signWith(key , SignatureAlgorithm.HS256) // 서명값
                    .compact();

        //TokenInfo
        return TokenInfo.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    //토큰 받아서 Authentication 반환
    public Authentication getAuthentication(String accessToken) throws ExpiredJwtException
    {
        //10
        //잠깐사이 예외 발생 토큰 만료 되면 다시 되돌아감
        Claims claims = Jwts.parser().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();

        String username = claims.getSubject(); //username
        username = (String)claims.get("username"); //username
        String auth = (String)claims.get("auth"); //"ROLE_USER, ROLE_ADMIN"

        //"ROLE_USER, ROLE_ADMIN" -> 문자열 추출
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        String roles [] =auth.split(",");//["ROLE_USER", "ROLE_ADMIN"]
        for(String role : roles){
            authorities.add(new SimpleGrantedAuthority(role));
        }
        //end 10
        //11
        PrincipalDetails principalDetails =  null ;
        UserDto dto = null ;
        if(userRepository.existsById(username)){ //계정 존재

            dto =  new UserDto();
            dto.setUsername(username);
            dto.setRole(auth);
            dto.setPassword(null);

            principalDetails = new PrincipalDetails(dto);
        }

        if(principalDetails != null){
            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(principalDetails,"",authorities);
            return authenticationToken;

        }

        return null;
    }


    //토큰 만료여부 체크 //9
    public boolean validateToken(String token) throws Exception //예외 발생시 호출했던 위치로 예외 던짐
    {
        boolean isValid = false;
        try {
            Jwts.parser().setSigningKey(key).build().parseClaimsJws(token); //토큰의 진위여부와 무결성 확인
            isValid = true; //만료 x
        }catch (ExpiredJwtException e){// 토큰 만료 예외
            log.info("[ExpiredJwtException].." + e.getMessage());
            throw new ExpiredJwtException(null,null,null);   //header,claims,message
        }
        return isValid;
    }

}
