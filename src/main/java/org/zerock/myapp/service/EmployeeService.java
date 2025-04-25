package org.zerock.myapp.service;

import java.util.Date;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;
import org.zerock.myapp.domain.EmployeeDTO;
import org.zerock.myapp.domain.EmployeeHierarchyDTO;
import org.zerock.myapp.domain.FileDTO;
import org.zerock.myapp.entity.Employee;

public interface EmployeeService {

	public abstract List<Employee> getAllList(); // 전체 조회

	public abstract Page<Employee> getSearchList(EmployeeDTO dto, Pageable paging); 		// 전체 조회(검색)
	public abstract Page<Employee> getSearchListData(EmployeeDTO dto, Pageable paging);	// 
	
	// 회원가입시 똑같은 아이디가 db에 저장되어 있는지 검증.
	public String generateEmpno(String rolePrefix, Date date);

	public abstract Boolean checkIdDuplicate(String loginId);

	public String getRolePrefixFromPosition(Integer position);

	public abstract Boolean create(EmployeeDTO dto, MultipartFile file);


	public abstract Employee getById(String id); // 단일 조회

	public abstract Boolean update(String empno, EmployeeDTO dto, MultipartFile file); // 수정 처리

	public abstract Boolean deleteById(String id);// 삭제 처리

	List<EmployeeHierarchyDTO> findByEnabledAndPositionInOrderByDepartment();

	List<Employee> getEmployeesByDepartmentId(Long deptId);

}// end interface