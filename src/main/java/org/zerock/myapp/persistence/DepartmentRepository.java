package org.zerock.myapp.persistence;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;
import org.zerock.myapp.entity.Department;


/**
 * 부서 Repository
 */

@Repository
public interface DepartmentRepository extends JpaRepository<Department, Long>, JpaSpecificationExecutor<Department> {

	Department findByIdAndEnabled(Long id, Boolean b);

	List<Department> findBypDeptIdAndEnabled(Long pDeptId, Boolean b);

	List<Department> findByEnabledAndIdNot(Boolean b, Long id);
} // end interface
