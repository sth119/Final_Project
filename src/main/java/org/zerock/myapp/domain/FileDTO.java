package org.zerock.myapp.domain;

import java.util.Date;

import org.zerock.myapp.entity.Employee;
import org.zerock.myapp.entity.Message;

import lombok.Data;


/**
 * 파일 DTO
 */

@Data
public class FileDTO {
	private Long id; // 파일 id
	
	private String original; // 원본명(확장자포함)
	private String uuid; // UUID명
	private String path; // 파일경로
	private Boolean enabled = true; // 활성화상태(1=유효,0=삭제)

	private Date crtDate; // 생성일
	private Date udtDate; // 수정일

	// join
	private Employee Employee; // 사원id
	private Message Message; // 메시지id
	
	private String searchWord; // 검색항목
	private String searchText; // 검색문
	
	
	public FileDTO(Long id, String original, String uuid, String path) {
	    this.id = id;
	    this.original = original;
	    this.uuid = uuid;
	    this.path = path;
	}
	
} // end class
