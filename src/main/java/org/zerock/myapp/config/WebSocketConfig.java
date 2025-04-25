package org.zerock.myapp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.server.standard.ServerEndpointExporter;
import org.zerock.myapp.handler.WebSocketChatHandler;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@AllArgsConstructor

//@EnableWebSocket
@Configuration						
public class WebSocketConfig implements WebSocketConfigurer {
	
	@Autowired private final WebSocketChatHandler chatHandler;
	
	@Override
	public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
		log.debug("registerWebSocketHandlers({}) invoked.",registry);

		registry.addHandler(chatHandler, "/chatroom").setAllowedOrigins("*");	
		
	}// registerWebSocketHandlers
	
	
	@Bean
	ServerEndpointExporter serverEndpointExporter() {
		log.debug("serverEndpointExporter() invoked.");
		return new ServerEndpointExporter();
	}// serverEndpointExporter

	
	
}// end class