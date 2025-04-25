package org.zerock.myapp.listener;

import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.PostRemove;
import jakarta.persistence.PostUpdate;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreRemove;
import jakarta.persistence.PreUpdate;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@NoArgsConstructor

public final class EntityLifecycleListener {
	
	
	@PrePersist 
	void prePersist(Object entity) {
		log.debug("(C) prePersist({}) invoked.", entity);
	}
	
	@PostPersist
	void postPersist(Object entity) {
		log.debug("(C) postPersist({}) invoked.", entity);
	}
	
	@PostLoad
	void postLoad(Object entity) {
		log.debug("(R) postLoad({}) invoked.", entity);
	}
	
	@PreUpdate
	void preUpdate(Object entity) {
		log.debug("(U) preUpdate({}) invoked.", entity);
	}
	
	@PostUpdate
	void postUpdate(Object entity) {
		log.debug("(U) postUpdate({}) invoked.", entity);
	} // postUpdate
	
	@PreRemove
	void preRemove(Object entity) {
		log.debug("(D) preRemove({}) invoked.", entity);
	}
	
	@PostRemove
	void postRemove(Object entity) {
		log.debug("(D) postRemove({}) invoked.", entity);
	}

} // end class