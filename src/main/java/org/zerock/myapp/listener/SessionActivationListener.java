package org.zerock.myapp.listener;

import lombok.NoArgsConstructor;
import lombok.extern.log4j.Log4j2;

import jakarta.servlet.http.HttpSessionActivationListener;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.annotation.WebListener;


@Log4j2

// Class contains `required fields`,
// you have to `force` NoArgsConstructor. (***)
@NoArgsConstructor

@WebListener
public class SessionActivationListener implements HttpSessionActivationListener {


    // Notification that the session is about to be passivated.
    @Override
    public void sessionWillPassivate(HttpSessionEvent se) {
        log.debug("---------------------------------------");
        log.debug("* sessionWillPassivate(se) invoked.");
        log.debug("---------------------------------------");

        log.info("\t+ session: {}", se.getSession().getId());
    } // sessionWillPassivate

    // Notification that the session has just been activated.
    @Override
    public void sessionDidActivate(HttpSessionEvent se) {
        log.debug("---------------------------------------");
        log.debug("* sessionDidActivate(se) invoked.");
        log.debug("---------------------------------------");

        log.info("\t+ session: {}", se.getSession().getId());
    } // sessionDidActivate

} // end class
