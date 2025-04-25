package org.zerock.myapp.domain;

import java.util.Date;
import java.util.List;
import java.util.Vector;

import org.zerock.myapp.entity.ChatEmployee;
import org.zerock.myapp.entity.Message;
import org.zerock.myapp.entity.Project;

import lombok.Data;


/**
 * 채팅 DTO
 */

@Data
public class ChatDTO {
	private Long id; // 채팅방 id

	private String name; // 채팅방명
	private Boolean enabled = true; // 활성화상태(1=유효,0=삭제)

	private Date crtDate; // 생성일
	private Date udtDate; // 수정일

	// join
	private Project project; // 프로젝트 뱃지 id
	private Long projectId;
	private List<ChatEmployee> chatEmployees = new Vector<>(); //  작성자 id 
	private List<String> empnos = new Vector<>();  // 생성 시 받아올 empno 리스트
	private List<Message> Messages = new Vector<>(); // 메시지 id
	
} // end class
