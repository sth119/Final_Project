package org.zerock.myapp.service;

import java.util.List;

import org.zerock.myapp.domain.MessageDTO;
import org.zerock.myapp.entity.Message;

public interface MessageService {
	public abstract List<Message> getByChatId(Long chatId);			// 해당 채팅방 메세지 리스트
	public abstract Message saveMessage(MessageDTO dto);			// 메세지 저장
	public abstract String summarizeMessage(Long id, String start, String end); // 메세지 요약
	
}//end interface 