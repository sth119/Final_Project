package org.zerock.myapp.entity;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;

import org.hibernate.annotations.CurrentTimestamp;
import org.hibernate.annotations.SourceType;
import org.hibernate.generator.EventType;
import org.zerock.myapp.domain.ChatDTO;
import org.zerock.myapp.util.BooleanToIntegerConverter;

import jakarta.persistence.Basic;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.Data;


@Data

// 채팅방 entity

@Entity
@Table(name="T_CHAT")
public class Chat implements Serializable {
	@Serial private static final long serialVersionUID = 1L;

	@Id @GeneratedValue(strategy = GenerationType.IDENTITY, generator = "ko")
	@SequenceGenerator(name = "ko", sequenceName = "T_CHAT_SEQ", initialValue = 1, allocationSize = 1)
	@Column(name = "ID", unique=true, nullable=false, length = 500)
	private Long id; // 채팅방 id

	@Column(nullable=false, length= 500)
	private String name; // 채팅방명

	@Convert(converter = BooleanToIntegerConverter.class)
	@Column(nullable=false, length= 500)
	private Boolean enabled = true; // 활성화상태(1=유효,0=삭제)

	@CurrentTimestamp(event = EventType.INSERT, source = SourceType.DB)
	@Basic(optional = false, fetch = FetchType.LAZY)
	private Date crtDate; // 생성일

	@CurrentTimestamp(event = EventType.UPDATE, source = SourceType.DB)
	@Column
	private Date udtDate; // 수정일

	// join
	@ManyToOne
	@JoinColumn(name="PJT_ID")
	private Project Project; // 프로젝트 뱃지 id
	
	
	public ChatDTO toDTO() {
	    ChatDTO dto = new ChatDTO();
	    dto.setId(this.id);
	    dto.setName(this.name);
	    dto.setEnabled(this.enabled);

	    if (this.Project != null) {
	        dto.setProject(this.Project);
	    }// if

	    return dto;
	}// toDTO

	

} // end class