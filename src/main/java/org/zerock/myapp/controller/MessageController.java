package org.zerock.myapp.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.zerock.myapp.entity.Message;
import org.zerock.myapp.service.MessageService;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * 메시지 Controller
 */

@Slf4j
@NoArgsConstructor

@RequestMapping("/message")
@RestController
public class MessageController {
	
	@Autowired private MessageService messageService;
	
	@GetMapping
	List<Message> ListByChatId(@RequestParam Long chatId) { // 리스트
		log.debug("delete({}) invoked.",chatId);
		
		return this.messageService.getByChatId(chatId);
	} // list

	
	@PostMapping(path = "/{id}/summarize")
	String summarize( // 요약
			@PathVariable Long id,
			@RequestParam String start, String end 			// 날짜 포함
			) {
		log.debug("summarize({}) invoked.",id);
		String result = this.messageService.summarizeMessage(id, start, end);
		
		return result;
	} // summarize
	
} // end class
