package com.example.demo.config.auth;

import com.example.demo.domain.dtos.UserDto;
import com.example.demo.domain.entity.User;
import com.example.demo.domain.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;
//5
@Service
@Slf4j
public class PrincipalDetailsService implements UserDetailsService{

    @Autowired
    private UserRepository userRepository;

    @Override //계정정보 전달 //DB대조 //UserDetailsService 상속받아서 로컬계정 받기
    public UserDetails loadUserByUsername(String username)throws UsernameNotFoundException{

        System.out.println("PrincipalDetailsService's loadUserByUsername : " + username);

        Optional<User> userOptional =
                userRepository.findById(username);
        if(userOptional.isEmpty()){
            throw new UsernameNotFoundException(username + "계정이 존재하지 않습니다.");
        }
        //Entity -> dto
        User user = userOptional.get();
        UserDto dto = new UserDto();
        dto.setUsername(user.getUsername());
        dto.setPassword(user.getPassword());
        dto.setRole(user.getRole());

        return new PrincipalDetails(dto);
    }

    //이러면 자동 로그인 처리
}
