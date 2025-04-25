package org.zerock.myapp.entity;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;

import org.hibernate.annotations.CurrentTimestamp;
import org.hibernate.annotations.SourceType;
import org.hibernate.generator.EventType;
import org.zerock.myapp.util.BooleanToIntegerConverter;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.Data;


@Data

//JSON 으로 변환해서 보낼때, 제외 할 항목
@JsonIgnoreProperties({
	"udtDate"
})

// 채팅메시지 entity

@Entity
@Table(name="T_MESSAGE")
public class Message implements Serializable {
	@Serial private static final long serialVersionUID = 1L;

	//1. pk
	@Id @GeneratedValue(strategy = GenerationType.IDENTITY, generator = "ko")
	@SequenceGenerator(name = "ko", sequenceName = "T_MESSAGE_SEQ", initialValue = 1, allocationSize = 1)
	@Column(name = "ID", unique=true, nullable=false)
	private Long id; // 메시지 id

	// 2-1. General Properties
	@Column(nullable=true, length = 4000)
	private String detail; // 내용

	@Convert(converter = BooleanToIntegerConverter.class)
	@Column(nullable=false)
	private Boolean enabled = true; // 활성화상태(1=유효,0=삭제)
	
	@CurrentTimestamp(event = EventType.INSERT, source = SourceType.DB)
	@Column(nullable=false)
	private Date crtDate; // 생성일
	
	
	@CurrentTimestamp(event = EventType.UPDATE, source = SourceType.DB)
	@Column
	private Date udtDate; // 수정일

	@Column(nullable = false, length = 20)
	private String type; // "MESSAGE", "JOIN", "LEAVE", "INVITE" 등

	@ManyToOne
	@JoinColumn(name="CHAT_ID")
	private Chat chat; // 채팅

	@ManyToOne
	@JoinColumn(name="EMPNO")
	private Employee Employee; // 사원

} // end class