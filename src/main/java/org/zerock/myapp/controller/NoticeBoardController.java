package org.zerock.myapp.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.zerock.myapp.domain.BoardDTO;
import org.zerock.myapp.entity.Board;
import org.zerock.myapp.exception.ServiceException;
import org.zerock.myapp.service.NoticeBoardService;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;


/**
 * 게시판(공지사항) Controller
 */

@Slf4j
@NoArgsConstructor

@RequestMapping("/board/notice")
@RestController
public class NoticeBoardController {
	
	@Autowired  
	private NoticeBoardService service;
	
	
	@GetMapping
	Page<Board> list(
			@ModelAttribute BoardDTO dto,
			@RequestParam(name = "currPage", required = false, defaultValue = "1") Integer currPage, // 페이지 시작 값은 0부터
			@RequestParam(name = "pageSize", required = false, defaultValue = "10") Integer pageSize // 기본 페이지 사이즈 8
		
			) { // 리스트
		log.debug("list({}) invoked.", dto);
		
		dto.setType(1); // 공지
		
		Pageable paging = PageRequest.of(currPage-1, pageSize, Sort.by("crtDate", "id").descending());	// Pageable 설정
		
		Page<Board> list = this.service.getSearchList(dto, paging); 
		
	
		
		return list;
	} // list
	
	@PostMapping("/create")
	Board create(@ModelAttribute BoardDTO dto) { // 등록 처리
		log.debug("register() invoked.");
		
		Board result = this.service.create(dto);
		
		return result;
	} // register
	
	@GetMapping(path = "/{id}")
	Board read( // 세부 조회
			@PathVariable Long id
			) {
		log.debug("read({}) invoked.",id);
		
		Board post = service.getById(id);
		
		return post;
	} // read
	
	@PutMapping(path = "/{id}")
	Board update( // 수정 처리
			@PathVariable Long id, @ModelAttribute BoardDTO dto
			) { 
		log.debug("update({}) invoked.",id);
		
		Board result = this.service.update(id, dto);
		
		return result;
	} // update
	
	@DeleteMapping(path = "/{id}")
	Board delete( // 삭제 처리
			@PathVariable Long id
			) throws ServiceException {
		
		Board result = this.service.deleteById(id);
		
		return result;
	} // delete
	

} // end class
