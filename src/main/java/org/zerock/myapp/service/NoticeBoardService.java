package org.zerock.myapp.service;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.zerock.myapp.domain.BoardDTO;
import org.zerock.myapp.entity.Board;
import org.zerock.myapp.exception.ServiceException;

public interface NoticeBoardService {


	public abstract Page<Board> getSearchList(BoardDTO dto, Pageable paging); // 전체 조회(검색)
	
	public abstract Board create(BoardDTO dto);    	// 생성 처리
	public abstract Board getById(Long id);    // 단일 조회
	public abstract Board update(Long id, BoardDTO dto);    	// 수정 처리
	public abstract Board deleteById(Long id) throws ServiceException;// 삭제 처리
	
	public abstract Optional<Board> listFeedbacksForCurrentUser();
	
}//end interface