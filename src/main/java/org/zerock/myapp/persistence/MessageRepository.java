package org.zerock.myapp.persistence;

import java.util.Date;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;
import org.zerock.myapp.entity.Message;


/**
 * 메시지 Repository
 */

@Repository
public interface MessageRepository extends JpaRepository<Message, Long>, JpaSpecificationExecutor<Message> {
	List<Message> findByChatIdOrderByCrtDate(Long chatId);
	List<Message> findByChatIdAndCrtDateBetweenOrderByCrtDate(Long chatId, Date startDate, Date endDate);
} // end interface
