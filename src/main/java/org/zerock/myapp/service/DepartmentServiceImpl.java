package org.zerock.myapp.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.zerock.myapp.domain.DepartmentDTO;
import org.zerock.myapp.entity.Department;
import org.zerock.myapp.entity.Employee;
import org.zerock.myapp.persistence.DepartmentRepository;
import org.zerock.myapp.persistence.EmployeeRepository;

import jakarta.annotation.PostConstruct;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@NoArgsConstructor

@Service
public class DepartmentServiceImpl implements DepartmentService {
    @Autowired DepartmentRepository dao;
    @Autowired EmployeeRepository eDao;
	
	
	@PostConstruct
    void postConstruct(){
        log.debug("DepartmentServiceImpl -- postConstruct() invoked");
        log.debug("dao: {}", dao);
    }//postConstruct

	@Override
	public List<Department> getAllList() {	//검색 없는 전체 리스트
		log.debug("DepartmentServiceImpl -- getAllList() invoked");
		
		List<Department> list = dao.findAll();
		
		
		return list;
	} // getAllList
	
	@Override
	public List<Department> findByEnabledAndIdNot(Boolean b, Long id) {
		
		List<Department> list = this.dao.findByEnabledAndIdNot(b, id);
		
		return list;
		
	} // findByEnabledAndIdNot
	
	@Override
	public DepartmentDTO getByIdAndEnabled(Long id, Boolean b) {	// 단일 조회
		log.debug("DepartmentServiceImpl -- getById({}) invoked", id);
		
		try {
			Department department = this.dao.findByIdAndEnabled(id, true);
			if(department == null) {
				log.error("잘못된 부서입니다. {}",id);
				return null;
				};
			log.info("department is : {}",department);
			
			// 재귀 변환 메서드 호출
	        return convertToNestedDto(department);

		} catch(Exception e) {
			log.error("잘못된 부서입니다. {}",e);
			return null;
		} // try-catch
	} // getById
	
	private DepartmentDTO convertToNestedDto(Department entity) {
		// 핵심 수정 부분: null 입력 방지
	    if (entity == null) {
	        log.warn("변환할 엔티티가 null입니다!");
	        return null;
	    } // if
		
	    // 기본 필드 매핑
	    DepartmentDTO dto = entity.toDto();
	    
	    // 부서 id로 사원 검색하여 삽입
	    List<Employee> employees = this.eDao.findByEnabledAndDepartment(true, entity);
	    dto.setEmployees(employees);
	    
	    // 현재 부서의 직계 하위 부서 조회
	    List<Department> childEntities = this.dao.findBypDeptIdAndEnabled(entity.getId(), true);
	    
	    // 재귀 변환 실행
	    List<DepartmentDTO> childDTOs = childEntities.stream()
	        .map(c -> convertToNestedDto(c))  // ★ 재귀 호출 ★
	        .collect(Collectors.toList());
	    
	    dto.setChildren(childDTOs);
	    
	    return dto;
	} // convertToNestedDto


}//end class
