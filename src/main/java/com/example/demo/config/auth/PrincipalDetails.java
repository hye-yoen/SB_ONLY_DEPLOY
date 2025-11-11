package com.example.demo.config.auth;

import com.example.demo.domain.dtos.UserDto;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

//6
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PrincipalDetails implements UserDetails, OAuth2User { //계정정보 자동 판단

    @Autowired
    private UserDto dto;

    Map<String,Object> attributes;

    public PrincipalDetails(UserDto dto){
        this.dto = dto;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();

//        authorities.add(new SimpleGrantedAuthority(dto.getRole()));
            String roles [] =dto.getRole().split(",");
            for(String role : roles){
                authorities.add(new SimpleGrantedAuthority(role));
            }

        return authorities; //롤을 권한 처리
    }

    //========================
    // OAuth2에 사용되는 속성 / 메서드
    //========================

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    //========================
    // 로컬인증에 사용되는 메서드
    //========================

    @Override
    public String getPassword() {
        return dto.getPassword();
    }

    @Override
    public String getUsername() {
        return dto.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() { // 계정의 만료 여부
        return true;
    }

    @Override
    public boolean isAccountNonLocked() { // 계정의 잠금 여부
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() { // 자격 증명(비밀번호)의 만료 여부
        return true;
    }

    @Override
    public boolean isEnabled() { //계정의 활성화 여부
        return true;
    }

    @Override
    public String getName() {
        return "";
    }
}
