package org.zerock.myapp.listener;

import lombok.NoArgsConstructor;
import lombok.extern.log4j.Log4j2;

import jakarta.servlet.ServletContextAttributeEvent;
import jakarta.servlet.ServletContextAttributeListener;
import jakarta.servlet.annotation.WebListener;


@Log4j2

// Class contains `required fields`, You have to `force` NoArgsConstructor. (***)
@NoArgsConstructor

@WebListener
public final class ApplicationScopeAttributeListener implements ServletContextAttributeListener {


	@Override
    public void attributeAdded(ServletContextAttributeEvent event) {
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
    	
    	String name = event.getName();
    	Object value = event.getValue();
    	
    	log.info("\t+ name: {}", name);
    	log.info("\t+ value: {}", value);
		log.info("\t+ type: {}", value.getClass().getName());
    } // attributeAdded

	@Override
	public void attributeRemoved(ServletContextAttributeEvent event) {
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
    	
    	String name = event.getName();
    	Object value = event.getValue();

		log.info("\t+ name: {}", name);
		log.info("\t+ value: {}", value);
		log.info("\t+ type: {}", value.getClass().getName());
    } // attributeRemoved

	@Override
	public void attributeReplaced(ServletContextAttributeEvent event) {
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
    	
    	String name = event.getName();
    	Object value = event.getValue();

		log.info("\t+ name: {}", name);
		log.info("\t+ value: {}", value);
		log.info("\t+ type: {}", value.getClass().getName());
    } // attributeReplaced
	
} // end class
