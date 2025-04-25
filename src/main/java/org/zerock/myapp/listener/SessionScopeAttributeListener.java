package org.zerock.myapp.listener;

import lombok.NoArgsConstructor;
import lombok.extern.log4j.Log4j2;

import jakarta.servlet.http.HttpSessionAttributeListener;
import jakarta.servlet.http.HttpSessionBindingEvent;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.annotation.WebListener;


@Log4j2

// Class contains `required fields`,
// you have to `force` NoArgsConstructor. (***)
@NoArgsConstructor

@WebListener
public class SessionScopeAttributeListener implements HttpSessionAttributeListener {

    
	@Override
	public void attributeAdded(HttpSessionBindingEvent event) {
    	if(
			event.getName().startsWith("org.springframework") || 
			event.getName().startsWith("org.apache") || 
			event.getName().startsWith("jakarta.servlet") || 
			event.getName().endsWith(".FILTERED")
		) {
    		return;
    	} // if

		log.debug("---------------------------------------");
    	log.debug("* attributeAdded(event) invoked.");
		log.debug("---------------------------------------");
    	
    	HttpSession session = event.getSession();
    	String name = event.getName();
    	Object value = event.getValue();
    	
    	log.info("\t+ session: {}", session.getId());
    	log.info("\t+ name: {}", name);
    	log.info("\t+ value: {}", value);
		log.info("\t+ type: {}", value.getClass().getName());
    } // attributeAdded


	@Override
	public void attributeRemoved(HttpSessionBindingEvent event) {
    	if(
			event.getName().startsWith("org.springframework") || 
			event.getName().startsWith("org.apache") || 
			event.getName().startsWith("jakarta.servlet") || 
			event.getName().endsWith(".FILTERED")
		) {
    		return;
    	} // if

		log.debug("---------------------------------------");
    	log.debug("* attributeRemoved(event) invoked.");
		log.debug("---------------------------------------");
    	
    	HttpSession session = event.getSession();
    	String name = event.getName();
    	Object value = event.getValue();
    	
    	log.info("\t+ session: {}", session.getId());
    	log.info("\t+ name: {}", name);
    	log.info("\t+ value: {}", value);
		log.info("\t+ type: {}", value.getClass().getName());
    } // attributeRemoved


	@Override
	public void attributeReplaced(HttpSessionBindingEvent event) {
    	if(
			event.getName().startsWith("org.springframework") || 
			event.getName().startsWith("org.apache") || 
			event.getName().startsWith("jakarta.servlet") || 
			event.getName().endsWith(".FILTERED")
		) {
    		return;
    	} // if

		log.debug("---------------------------------------");
    	log.debug("* attributeReplaced(event) invoked.");
		log.debug("---------------------------------------");
    	
    	HttpSession session = event.getSession();
    	String name = event.getName();
    	Object value = event.getValue();
    	
    	log.info("\t+ session: {}", session.getId());
    	log.info("\t+ name: {}", name);
    	log.info("\t+ value: {}", value);
		log.info("\t+ type: {}", value.getClass().getName());
    } // attributeReplaced
	
} // end class
