package org.zerock.myapp.controller;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.zerock.myapp.domain.EmployeeDTO;
import org.zerock.myapp.domain.TokenResponseDto;
import org.zerock.myapp.entity.Employee;
import org.zerock.myapp.secutity.JwtProvider;
import org.zerock.myapp.service.LoginServiceImpl;
import org.zerock.myapp.util.RoleUtil;

@RequestMapping("/auth")
@RestController
public class LoginController {

	
	@Autowired LoginServiceImpl service;
	@Autowired JwtProvider jwt;
	@Autowired AuthenticationManager AuthManager;
	
	
	
	@PostMapping("/login")
	ResponseEntity<?> login( // ResponseEntity<?> :Spring 에서 http 응답 전체를 커스터마이징 하고 싶을때 사용하는 클래
			@ModelAttribute EmployeeDTO dto
	) {	
		
	try {
	    Optional<Employee> employeecheck = service.login(dto.getLoginId(), dto.getPassword());

	    if (employeecheck.isEmpty()) {
	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
	        		.body(Map.of("error", "로그인 실패. 인증된 사용자가 아닙니다."));
	    }

	    Employee employee = employeecheck.get();
	    
	    // 1. 인증 성공 후 SecurityContext 등록. 이 과정을 통해서 security의 인가를 사용할 수 있음.
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(
                        employee.getLoginId(), null, getAuthorities(employee)
                );
        SecurityContextHolder.getContext().setAuthentication(authToken);
        
        
        
        
        // JWT 토큰 발급
	    String token = JwtProvider.generateToken(dto.getLoginId(), employee);  // 여기서 생성
	    long expiresAt = System.currentTimeMillis() + 3600 * 1000; // 1시간 후 만료.

	
	    TokenResponseDto response = new TokenResponseDto(token, expiresAt);
	    return ResponseEntity.ok(response);  // 토큰 클라이언트에 반환
	    
	} catch (IllegalArgumentException e) {
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
				.body(Map.of("error", e.getMessage()));
	}

	} // end login
	
	private List<GrantedAuthority> getAuthorities(Employee emp) {
	    String roleName = RoleUtil.mapPositionToRole(emp.getPosition());   // 예: "DepartmentLeader"
	    return List.of(new SimpleGrantedAuthority("ROLE_" + roleName));    // 예: "ROLE_DepartmentLeader"
	}
	
	
	@GetMapping("/myinfo")
	public ResponseEntity<?> getMyInfo(Authentication authentication) {
		String loginId = authentication.getName();
		return ResponseEntity.ok("반가워요. " + loginId + "님 !");
	}
	

	
}
