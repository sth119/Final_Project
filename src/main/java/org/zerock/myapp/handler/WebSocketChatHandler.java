package org.zerock.myapp.handler;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import org.zerock.myapp.domain.MessageDTO;
import org.zerock.myapp.entity.Employee;
import org.zerock.myapp.persistence.EmployeeRepository;
import org.zerock.myapp.service.MessageService;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Component
public class WebSocketChatHandler extends TextWebSocketHandler {

    @Autowired private ObjectMapper objectMapper;
    @Autowired private final MessageService messageService;
    @Autowired private EmployeeRepository employeeRepository;

    private final Map<Long, Set<WebSocketSession>> chatRoomSessions = new ConcurrentHashMap<>();
    private final Map<String, Set<WebSocketSession>> userSessions = new ConcurrentHashMap<>();

    public Map<Long, Set<WebSocketSession>> getChatRoomSessions() {
        return this.chatRoomSessions;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        log.debug("afterConnectionEstablished({}) invoked.", session);

        Long chatId = getChatIdFromSession(session);
        String empno = getEmpnoFromSession(session);

        chatRoomSessions.computeIfAbsent(chatId, k -> ConcurrentHashMap.newKeySet()).add(session);
        userSessions.computeIfAbsent(empno, k -> ConcurrentHashMap.newKeySet()).add(session);
    } // afterConnectionEstablished

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) {
        log.debug("handleTextMessage({}, {}) invoked.", session, message);

        try {
            MessageDTO messageDTO = objectMapper.readValue(message.getPayload(), MessageDTO.class);
            Long chatId = getChatIdFromSession(session);

            Optional<Employee> optEmployee = employeeRepository.findById(messageDTO.getEmpno());
            if (optEmployee.isEmpty()) {
                throw new RuntimeException("사원 정보 없음: " + messageDTO.getEmpno());
            }
            Employee employee = optEmployee.get();
            messageDTO.setEmployee(employee);

            broadcastToChatRoom(chatId, messageDTO);
            messageService.saveMessage(messageDTO);

        } catch (IOException e) {
            log.error("메시지 처리 중 오류 발생", e);
        } // try
    } // handleTextMessage

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        log.debug("afterConnectionClosed({}, {}) invoked.", session, status);

        Long chatId = getChatIdFromSession(session);
        Set<WebSocketSession> sessions = chatRoomSessions.get(chatId);
        if (sessions != null) {
            sessions.remove(session);
        }
    } // afterConnectionClosed

    private Long getChatIdFromSession(WebSocketSession session) {
        String query = session.getUri().getQuery();
        if (query == null || !query.contains("chatId=")) {
            throw new IllegalArgumentException("chatId 파라미터가 존재하지 않습니다: " + query);
        }

        try {
            for (String param : query.split("&")) {
                if (param.startsWith("chatId=")) {
                    return Long.parseLong(param.substring("chatId=".length()));
                }
            }
            throw new IllegalArgumentException("chatId 파라미터 누락");
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("chatId는 숫자 형식이어야 합니다: " + query);
        } // try
    } // getChatIdFromSession

    private String getEmpnoFromSession(WebSocketSession session) {
        String query = session.getUri().getQuery();
        if (query == null || !query.contains("empno=")) {
            throw new IllegalArgumentException("empno 파라미터가 존재하지 않습니다: " + query);
        }

        for (String param : query.split("&")) {
            if (param.startsWith("empno=")) {
                return param.substring("empno=".length());
            }
        } // for

        throw new IllegalArgumentException("empno 파라미터 형식이 잘못되었습니다");
    } // getEmpnoFromSession

    public void broadcastToChatRoom(Long chatId, MessageDTO messageDTO) {
        Set<WebSocketSession> sessions = chatRoomSessions.get(chatId);
        if (sessions != null) {
            try {
                String messageJson = objectMapper.writeValueAsString(messageDTO);
                for (WebSocketSession session : sessions) {
                    session.sendMessage(new TextMessage(messageJson));
                }
            } catch (IOException e) {
                log.error("브로드캐스트 실패", e);
            } // try
        }
    } // broadcastToChatRoom
} // end class
