package org.zerock.myapp.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.zerock.myapp.domain.ChatDTO;
import org.zerock.myapp.entity.Chat;
import org.zerock.myapp.entity.ChatEmployee;
import org.zerock.myapp.service.ChatService;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * 채팅 Controller
 */

@Slf4j
@NoArgsConstructor

@RequestMapping("/chat")
@RestController
public class ChatController {

	@Autowired private ChatService chatService;
	
	@GetMapping(path = "/list/{empno}")
	List<ChatEmployee> myList(@PathVariable String empno) { // 리스트
		log.debug("list() invoked.");
		return this.chatService.findMyList(empno);
	} // list	
	
	@PostMapping
	Chat register(@ModelAttribute ChatDTO dto, @RequestParam String empno) { // 등록 처리
		log.debug("register() invoked.");
		
		return this.chatService.createRoom(dto, empno);
	} // register
	
	@GetMapping(path = "/{id}")
	ChatDTO read( // 세부 조회
			@PathVariable Long id
			) {
		log.debug("read({}) invoked.",id);
		
		return this.chatService.getById(id);
	} // read
	
	@PutMapping(path = "/{id}")
	Boolean update( 			// 수정 처리
			@ModelAttribute ChatDTO dto,
			@PathVariable Long id
			) { 
		log.debug("update({}) invoked.",id);
		
		return this.chatService.update(dto,id);
	} // update
	
	@DeleteMapping(path = "/{id}")
	Chat delete( // 삭제 처리
			@PathVariable Long id,
			@RequestParam String empno
			) {
		log.debug("delete({}) invoked.",id);
		
		return this.chatService.deleteById(id,empno);
	} // delete
	
	
} // end class
