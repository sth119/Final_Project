package org.zerock.myapp.domain;

import java.util.List;
import java.util.Vector;

import org.zerock.myapp.entity.Employee;

import lombok.Data;

@Data
public class DepartmentDTO {
	
	private Long id;
	
    private String name;
    private Integer depth;
    private Boolean enabled;
    
    private Long pDeptId;
    
    
    private List<DepartmentDTO> children = new Vector<>();
    private List<Employee> employees = new Vector<>(); 
   
} // end class
