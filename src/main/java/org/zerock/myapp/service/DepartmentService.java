package org.zerock.myapp.service;

import java.util.List;

import org.zerock.myapp.domain.DepartmentDTO;
import org.zerock.myapp.entity.Department;

public interface DepartmentService {
	
	public abstract DepartmentDTO getByIdAndEnabled(Long id, Boolean b);    // 단일 조회
	
	public abstract List<Department> getAllList();
	
	public abstract List<Department> findByEnabledAndIdNot(Boolean b, Long id);
	
}//end interface