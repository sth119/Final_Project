package org.zerock.myapp.runner;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.zerock.myapp.service.MessageService;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@NoArgsConstructor

@Component
public class CLIRunner implements CommandLineRunner{
	@Autowired private MessageService service;
	

	@Override
	public void run(String... args) throws Exception {
		log.debug("run({}) invoked.", Arrays.toString(args));		
		log.info(">>>>>>>>>>>>>>>>>>>>>>>>>>>> service:{}", this.service);		
	}

} // end class

