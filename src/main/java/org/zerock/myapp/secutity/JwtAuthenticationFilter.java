package org.zerock.myapp.secutity;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {


private final JwtProvider jwtProvider;

public JwtAuthenticationFilter(JwtProvider jwtProvider) {
    this.jwtProvider = jwtProvider;
}

@Override
protected void doFilterInternal(HttpServletRequest request,
                                HttpServletResponse response,
                                FilterChain filterChain)
                                throws ServletException, IOException {

    // 1. Authorization 헤더에서 Bearer 토큰 꺼내기
    String authHeader = request.getHeader("Authorization");
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        filterChain.doFilter(request, response);
        return;
    }
    String token = authHeader.substring(7);

    try {
        // 2. JWT 검증 + 디코딩 (issuer, signature 검사)
        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC256("mySuperSecretKey12345"))
                                   .withIssuer("Mark")
                                   .build()
                                   .verify(token);

        // 3. Subject(=username) 및 기타 클레임 추출
        String username   = decodedJWT.getSubject();
        String empno      = decodedJWT.getClaim("empno").asString();
        List<String> roles= decodedJWT.getClaim("roles").asList(String.class);
        String name       = decodedJWT.getClaim("name").asString();
        String loginId    = decodedJWT.getClaim("loginId").asString();
        String password   = decodedJWT.getClaim("password").asString();
        String tel        = decodedJWT.getClaim("tel").asString();
        String address    = decodedJWT.getClaim("address").asString();
        Integer zipCode   = decodedJWT.getClaim("zipCode").asInt();
        String email      = decodedJWT.getClaim("email").asString();
        Integer position  = decodedJWT.getClaim("position").asInt();
        String department = decodedJWT.getClaim("department").asString();

        
        
        if (roles == null || roles.isEmpty()) {
            System.out.println("JWT에 roles 정보 없음");
            filterChain.doFilter(request, response);
            return;
        }

        // 4. GrantedAuthority 리스트 생성
        Collection<GrantedAuthority> authorities = roles.stream()
            .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
//            .map(SimpleGrantedAuthority::new) // 있는 문자열 그대로 "employee"
            .collect(Collectors.toList());

        // 5. Principal 생성 및 SecurityContext에 Authentication 주입
        JwtPrincipal principal = new JwtPrincipal(
        		empno,roles.get(0),name,loginId,password,tel,address,zipCode,email,position,department
        );

        Authentication auth = new UsernamePasswordAuthenticationToken(principal, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(auth);

        System.out.println("JWT 필터 통과: " + username + ", 권한: " + roles);

    } catch (Exception e) {
        System.out.println("JWT 검증 실패: " + e.getMessage());
    }

    filterChain.doFilter(request, response);
}




}