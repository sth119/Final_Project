package org.zerock.myapp.persistence;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.zerock.myapp.entity.Employee;

@Repository
public interface LoginRepository extends JpaRepository<Employee, String> {

	
	// DB에 아이디가 있는지 검증
	public abstract Optional<Employee> findByLoginId(String loginId);
	
	
}
