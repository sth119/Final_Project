package org.zerock.myapp.service;

import java.util.Optional;

import org.springframework.stereotype.Service;
import org.zerock.myapp.entity.Employee;

@Service
public interface LoginService {

	public abstract Optional<Employee>findByLoginId(String loginId);
	public abstract Boolean checkPassword(String rowPassword, String encodedPassword);
	public abstract Optional<Employee> login(String loginId, String password);

	
} // end service
