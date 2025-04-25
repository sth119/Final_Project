package org.zerock.myapp.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.zerock.myapp.domain.DepartmentDTO;
import org.zerock.myapp.entity.Department;
import org.zerock.myapp.service.DepartmentServiceImpl;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * 부서 Controller
 */

@Slf4j
@NoArgsConstructor

@RequestMapping("/department")
@RestController
public class DepartmentController {
    @Autowired private DepartmentServiceImpl service;
	
    @GetMapping
	public List<Department> list() { // 리스트
		log.debug("list() invoked.");
		
		List<Department> list = service.getAllList();
		
		return list;
	} // list
    
    
    @GetMapping("/filter")
    public List<Department> filteredList() {
    	
    	List<Department> list = service.findByEnabledAndIdNot(true, 1L);
    	
    	return list;
    }
    
    
	@GetMapping(path = "/{id}")
	DepartmentDTO read(@PathVariable Long id) { // 세부 조회
		log.debug("read({}) invoked.",id);
		
		// id를 통해 부서 조회
		// 전부조회 = 1(회사)
		DepartmentDTO dto =this.service.getByIdAndEnabled(id, true);
		
		return dto;
	} // read

} // end class
