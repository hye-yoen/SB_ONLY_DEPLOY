package com.example.demo.controller;

import com.example.demo.config.auth.PrincipalDetails;
import com.example.demo.domain.dtos.UserDto;
import com.example.demo.domain.entity.User;
import com.example.demo.domain.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.io.IOException;

@Controller
@Slf4j
public class UserController {

    @Autowired
    private HttpServletResponse response;
    @Autowired
    private HttpServletRequest request;

    @GetMapping("/login")
    public void login( @AuthenticationPrincipal PrincipalDetails principalDetails)throws IOException{
        log.info("GET /login..controller");
        String endPoint = request.getRequestURI();
        if(principalDetails != null){
            response.sendRedirect("/user");
        }
    }

    //유저정보 꺼내오기
    //1. 기본 authentication Bean 주입
//    @GetMapping("/user")
//    public void user(Authentication authentication, Model model){ //model -> thymeleaf
//        log.info("GET /user..." + authentication);
//        log.info("name ... : "+ authentication.getName());
//        log.info("principal..."+ authentication.getPrincipal()); //principal에서 만들어진 단위
//        log.info("authorities..." + authentication.getAuthorities()); //role 확인
//        log.info("details ..." + authentication.getDetails()); //상세정보 (세션 정보 등등)
//        log.info("credential..." + authentication.getCredentials()); //비닐번호 , 없는 걸로 표시
//
//        model.addAttribute("auth_1",authentication);
//    }
    //2. 방법 //SecurityContextHolder에 접근해서 꺼내는 방법
    @GetMapping("/user")
    public void user(Model model){ //model -> thymeleaf

        Authentication authentication =
        SecurityContextHolder.getContext().getAuthentication();

        log.info("GET /user..." + authentication);
        log.info("name ... : "+ authentication.getName());
        log.info("principal..."+ authentication.getPrincipal()); //principal에서 만들어진 단위
        log.info("authorities..." + authentication.getAuthorities()); //role 확인
        log.info("details ..." + authentication.getDetails()); //상세정보 (세션 정보 등등)
        log.info("credential..." + authentication.getCredentials()); //비닐번호 , 없는 걸로 표시

        model.addAttribute("auth_1",authentication);
    }
    //확인 방법 -3 //Authentication's Principal만 꺼내서 사용
    @GetMapping("/manager") //스프링 부트 단독
    public void manager(@AuthenticationPrincipal PrincipalDetails principalDetails){
        log.info("GET /manager..." + principalDetails);
    }


    @GetMapping("/admin")
    public void admin(){
        log.info("GET /admin");
    }

    @GetMapping("/join")
    public void join(){
        log.info("GET /join..");
    }

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @PostMapping("/join")
    public String join_post(UserDto dto){
        log.info("POST /join_post.." + dto);
        String pwd = passwordEncoder.encode(dto.getPassword()); //암호화 -> security config에서 password 빈 설정

        //dto -> entity
        User user = new User();
        user.setUsername(dto.getUsername());
        user.setPassword(pwd);
        user.setRole("ROLE_USER");
        userRepository.save(user);
        boolean isJoin = true;
        if(isJoin){
            return "redirect:/login";
        }

        return "join";
    }

}
