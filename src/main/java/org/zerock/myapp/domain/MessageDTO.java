package org.zerock.myapp.domain;

import java.util.Date;
import java.util.List;
import java.util.Vector;

import org.zerock.myapp.entity.Chat;
import org.zerock.myapp.entity.Employee;
import org.zerock.myapp.entity.UpFile;

import lombok.Data;


/**
 * 메시지 DTO
 */

@Data
public class MessageDTO {
	private Long id; // 메시지 id

	private String detail; // 내용
	private Boolean enabled = true; // 활성화상태(1=유효,0=삭제)
	
	private Date crtDate; // 생성일
	private String type;	// 메세지 유형
	
	private List<String> invitedEmpnos; // 초대한 사람들 (invite 메시지용)
	// join
	private List<UpFile> Files = new Vector<>(); // 파일
	private Chat Chat; // 채팅
	private Long chatId;
	private String empno;
	private Employee Employee; // 사원

	
} // end class
