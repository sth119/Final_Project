package org.zerock.myapp.listener;

import lombok.NoArgsConstructor;
import lombok.extern.log4j.Log4j2;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;


@Log4j2

// Class contains `required fields`,
// you have to `force` NoArgsConstructor. (***)
@NoArgsConstructor

@WebListener
public class ContextListener implements ServletContextListener {


    @Override
    public void contextInitialized(ServletContextEvent sce) {
        log.debug("---------------------------------------");
        log.debug("* contextInitialized(sce) invoked.");
        log.debug("---------------------------------------");

        String contextPath = sce.getServletContext().getContextPath();
        log.info("\t+ contextPath: {}", "".equals(contextPath)? "/" : contextPath);
    } // contextInitialized

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        log.debug("---------------------------------------");
        log.debug("* contextDestroyed(sce) invoked.");
        log.debug("---------------------------------------");

        String contextPath = sce.getServletContext().getContextPath();
        log.info("\t+ contextPath: {}", "".equals(contextPath)? "/" : contextPath);
    } // contextDestroyed

} // end class
