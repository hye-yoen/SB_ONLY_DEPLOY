package com.example.demo.config.auth.jwt;

import java.security.SecureRandom;

public class KeyGenerator {

    //암호문 키 생성 키값 바디트로 반환
    public static byte[] keygen()
    {
        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[256 / 8]; //256비드 키 생성
        secureRandom.nextBytes(keyBytes);  // 난수로 바이트 배열 생성
        System.out.println("KeyGenerator getKeygen Key : " + keyBytes);
        return keyBytes;
    }
}
