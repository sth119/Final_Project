package org.zerock.myapp.listener;

import lombok.NoArgsConstructor;
import lombok.extern.log4j.Log4j2;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionBindingEvent;
import jakarta.servlet.http.HttpSessionBindingListener;
import jakarta.servlet.annotation.WebListener;


@Log4j2

// Class contains `required fields`,
// you have to `force` NoArgsConstructor. (***)
@NoArgsConstructor

@WebListener
public class SessionBindingListener implements HttpSessionBindingListener {


    @Override
    public void valueBound(HttpSessionBindingEvent event) {
        log.debug("---------------------------------------");
        log.debug("* valueBound(event) invoked.");
        log.debug("---------------------------------------");

        HttpSession session = event.getSession();
        String key = event.getName();
        Object value = event.getValue();
        String valueType = value.getClass().getName();

        log.info("\t+ session: {}", session.getId());
        log.info("\t+ key: {}", key);
        log.info("\t+ value: {}, type: {}", value, valueType);
    } // valueBound

    @Override
    public void valueUnbound(HttpSessionBindingEvent event) {
        log.debug("---------------------------------------");
        log.debug("* valueUnbound(event) invoked.");
        log.debug("---------------------------------------");

        HttpSession session = event.getSession();
        String key = event.getName();
        Object value = event.getValue();
        String valueType = value.getClass().getName();

        log.info("\t+ session: {}", session.getId());
        log.info("\t+ key: {}", key);
        log.info("\t+ value: {}, type: {}", value, valueType);
    } // valueUnbound

} // end class
