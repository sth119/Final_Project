package org.zerock.myapp.persistence;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;
import org.zerock.myapp.entity.Board;
import org.zerock.myapp.entity.Employee;
import org.zerock.myapp.entity.Project;


/**
 * 게시판(공지사항 + 건의사항) Repository
 */

@Repository
public interface BoardRepository extends JpaRepository<Board, Long>, JpaSpecificationExecutor<Board> {

	//게시판 별 유효한 전체 게시물
	public abstract Page<Board> findByEnabledAndType(Boolean enabled, Integer type, Pageable paging);
	
	//게시판 별 유효한 전체 게시물 + 제목
	public abstract Page<Board> findByEnabledAndTypeAndTitleContaining(Boolean enabled, Integer type, String Title, Pageable paging);
	
	//게시판 별 유효한 전체 게시물 + 작성자
	public abstract Page<Board> findByEnabledAndTypeAndEmployee_NameContaining(Boolean enabled, Integer type, String name, Pageable paging);
	
	


	//건의사함 작성자 본인 글만 리스트없
	public abstract Page<Board> findByEnabledAndTypeAndEmployee_Empno(Boolean enabled, Integer type, String empno, Pageable paging);
	
	//게시판 별 유효한 전체건의사함 작성자 본인 글만  + 제목
	public abstract Page<Board> findByEnabledAndTypeAndTitleContainingAndEmployee_Empno(Boolean enabled, Integer type, String Title, String empno, Pageable paging);
	
	//게시판 별 유효한 전체 게시물 + 작성자
	public abstract Page<Board> findByEnabledAndTypeAndEmployee_EmpnoAndEmployee_NameContaining(Boolean enabled, Integer type, String empno, String name, Pageable paging);
	
	
	
	
	public abstract Optional<Board> findByEnabledAndId(Boolean enabled, Long id);

	
} // end interface
