package org.zerock.myapp.entity;

import java.io.Serial;
import java.io.Serializable;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.Data;


@Data

// 업무-사원 PK 엔티티

@Embeddable
public class WorkEmployeePK implements Serializable {
	@Serial private static final long serialVersionUID = 1L;

	@Column(name="WORK_ID")
	private Long workId;

	@Column(name="EMPNO")
	private String empno;

} // end class