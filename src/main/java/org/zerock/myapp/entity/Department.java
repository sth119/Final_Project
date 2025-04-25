package org.zerock.myapp.entity;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;

import org.hibernate.annotations.CurrentTimestamp;
import org.hibernate.annotations.SourceType;
import org.hibernate.generator.EventType;
import org.zerock.myapp.domain.DepartmentDTO;
import org.zerock.myapp.util.BooleanToIntegerConverter;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.Data;


@Data

// 부서 entity

@Entity
@Table(name="T_DEPARTMENT")
public class Department implements Serializable {
	@Serial private static final long serialVersionUID = 1L;

	//1. pk
	@Id @GeneratedValue(strategy = GenerationType.IDENTITY, generator = "ko")
	@SequenceGenerator(name = "ko", sequenceName = "T_DEPARTMENT_SEQ", initialValue = 1, allocationSize = 1)
	@Column(name = "ID", unique=true, nullable=false)
	private Long id; // 부서 id

	@Column(nullable=false, length = 255)
	private String name; // 부서명

	@Column(nullable=false)
	private Integer depth; // 계층 깊이

	@Convert(converter = BooleanToIntegerConverter.class)
	@Column(nullable=false)
	private Boolean enabled = true; // 활성화상태(1=유효,0=삭제)

	
	@CurrentTimestamp(event = EventType.INSERT, source = SourceType.DB)
	@Column(nullable = false)
	private Date crtDate;

	@CurrentTimestamp(event = EventType.UPDATE, source = SourceType.DB)
	@Column
	private Date udtDate;
	
	@Column(name="P_DEPT_ID")
	private Long pDeptId; // 상위부서
	
	public DepartmentDTO toDto() {
		DepartmentDTO dto = new DepartmentDTO();
		dto.setId(this.id);
		dto.setName(this.name);
		dto.setDepth(this.depth);
		dto.setEnabled(this.enabled);
		dto.setPDeptId(this.pDeptId);

	    return dto;
	} // toDto


} // end class