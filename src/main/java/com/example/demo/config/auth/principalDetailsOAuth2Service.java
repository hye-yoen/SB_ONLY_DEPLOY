package com.example.demo.config.auth;

import com.example.demo.config.auth.provider.GoogleUserInfo;
import com.example.demo.config.auth.provider.KakaoUserInfo;
import com.example.demo.config.auth.provider.NaverUserInfo;
import com.example.demo.config.auth.provider.OAuth2UserInfo;
import com.example.demo.domain.dtos.UserDto;
import com.example.demo.domain.entity.User;
import com.example.demo.domain.repository.UserRepository;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;

@Service
@Slf4j
public class principalDetailsOAuth2Service extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("");
//        System.out.println("userRequest : "+ userRequest);
//        System.out.println("userRequest.getClientRegistration : "+ userRequest.getClientRegistration());
//        System.out.println("userRequest.getAccessToken : "+ userRequest.getAccessToken());
//        System.out.println("userRequest.getAdditionalParameters : "+userRequest.getAdditionalParameters());
//        System.out.println("userRequest.getAccessToken.getTokenValue : "+ userRequest.getAccessToken().getTokenValue());
//        System.out.println("userRequest.getAccessToken().getTokenType().getValue() : "+ userRequest.getAccessToken().getTokenType().getValue());
//        System.out.println("userRequest.getAccessToken().getScopes() : "+ userRequest.getAccessToken().getScopes());
        System.out.println("");

        OAuth2User oAuth2User = super.loadUser(userRequest);
        //키 value 값 확인
        System.out.println("oAuth2User : " + oAuth2User);
        System.out.println("oAuth2User.getAttributes() : " + oAuth2User.getAttributes());
        System.out.println("provider Name : " + userRequest.getClientRegistration().getClientName()); //구분용


        String provider = userRequest.getClientRegistration().getClientName();
        Map<String, Object> attributes = oAuth2User.getAttributes();

        OAuth2UserInfo oAuth2UserInfo = null;
        String username = null;
        if (provider.startsWith("Kakao")) {

            Long id = (Long) attributes.get("id");
            LocalDateTime connected_at = OffsetDateTime.parse(attributes.get("connected_at").toString()).toLocalDateTime();
            Map<String, Object> properties = (Map<String, Object>) attributes.get("properties");
            Map<String, Object> kakao_account = (Map<String, Object>) attributes.get("kakao_account");
            System.out.println("id : " + id);
            System.out.println("connected_at : " + connected_at);
            System.out.println("properties : "+ properties);
            System.out.println("kakao_account : " + kakao_account);

            oAuth2UserInfo = KakaoUserInfo.builder()
                    .id(id)
                    .connected_at(connected_at)
                    .properties(properties)
                    .kakao_account(kakao_account)
                    .build();
            //DB등록 계정명
            username = oAuth2UserInfo.getProvider() + "-" + oAuth2UserInfo.getProviderId();

        }
        else if (provider.startsWith("Naver")) {
            Map<String, Object> response = (Map<String, Object>) attributes.get("response");
            System.out.println( "response : " + response);
            oAuth2UserInfo = NaverUserInfo.builder()
                    .response(response)
                    .build();
            //DB등록 계정명
            username = oAuth2UserInfo.getEmail();
        }
        else if (provider.startsWith("Google")) {
            oAuth2UserInfo = GoogleUserInfo.builder()
                    .attributes(attributes)
                    .build();

            username = oAuth2UserInfo.getEmail();
        }
        System.out.println("oAuth2UserInfo : " + oAuth2UserInfo);

        // OAuth2 정보 -> 로컬계정생성(계정 X : 생성, 계정 O : 불러오기)
        String password = passwordEncoder.encode("1234");
        //DB내용조회
        Optional<User> userOptional = userRepository.findById(username);
        UserDto dto = null;
        if (userOptional.isEmpty()) {
            User user = new User();
            user.setUsername(username);
            user.setPassword(password);
            user.setRole("ROLE_USER");
            userRepository.save(user);

            dto = new UserDto(username, password, "ROLE_USER");
        } else {
            User user = userOptional.get();
            dto = new UserDto(username, user.getPassword(), user.getRole());
        }


        //principalDetails 로 변환해서 반환
        dto.setProvider(provider);
        dto.setProvider(oAuth2UserInfo.getProvider());
        return new PrincipalDetails(dto, oAuth2UserInfo.getAttributes()); // dto , attributes 전달
    }

}
