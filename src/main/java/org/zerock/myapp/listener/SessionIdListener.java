package org.zerock.myapp.listener;

import lombok.NoArgsConstructor;
import lombok.extern.log4j.Log4j2;

import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionIdListener;
import jakarta.servlet.annotation.WebListener;


@Log4j2

// Class contains `required fields`,
// you have to `force` NoArgsConstructor. (***)
@NoArgsConstructor

@WebListener
public class SessionIdListener implements HttpSessionIdListener {


    @Override
    public void sessionIdChanged(HttpSessionEvent se, String oldSessionId) {
        log.debug("---------------------------------------");
        log.debug("* sessionIdChanged(se, oldSessionId: {}) invoked.", oldSessionId);
        log.debug("---------------------------------------");

        log.info("\t+ oldSession: {} -> newSession: {}", oldSessionId, se.getSession().getId());
    } // sessionIdChanged

} // end class
