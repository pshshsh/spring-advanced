package org.example.expert.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import java.util.UUID;
import java.util.logging.Handler;

@Slf4j
public class LogInterceptor implements HandlerInterceptor {

  public static final String LOG_ID = "logId";

  // 컨트롤 호출 전에 실행 true 반환하면 다음단계로 넘어감
  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

    String requestURI = request.getRequestURI(); //클라이언트가 요청한 URL 경로가져옴
    String uuid = UUID.randomUUID().toString(); // 요청을 고유하게 구분할 수 있는 UUID 생성(요청마다 다른ID부여)
    String userId = request.getHeader("user-id");
    String userRole = request.getHeader("user-role");

    request.setAttribute(LOG_ID, uuid); // UUID를 Requst 속성에 저장(Requset 객체는 전체 요청 흐름동안 데이터 유지)


    if(userId == null || userRole == null){
      log.warn("로그인되지 않은 유저 - URL : {} ", requestURI);
      return false;
    }
    boolean isAdminEndpoint = requestURI.startsWith("/admin");
    if (isAdminEndpoint && !"ADMIN".equals(userRole)) {
      log.warn("권한 없는 사용자 접근 차단 - 사용자 ID: {}, URL: {}", userId, requestURI);
      response.sendError(HttpServletResponse.SC_FORBIDDEN, "관리자 권한이 필요합니다.");
      return false;
    }

    // handler가 @RequestMapping, @GetMapping, @PostMapping으로 매핑된 메서드 정보에 접근가능
    if (handler instanceof HandlerMethod){
      HandlerMethod handler1 = (HandlerMethod) handler;
    }
    log.info("preHandle 호출됨 - UUID: {}, URL: {}, HANDLER : {}", uuid, requestURI, handler);
    return true;
  }

  // 컨트롤러가 실행된 후 호출
  @Override
  public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
    log.info("postHandle [{}]", modelAndView);
  }

  // 응답이 완료 된 후 호출
  @Override
  public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
    String requestURI = request.getRequestURI();
    String logId = (String) request.getAttribute(LOG_ID);

    log.info("afterCompletion 호출됨 - UUID: {}, URL: {}", logId, requestURI);
    if (ex != null) {
      log.error("Exception 발생!", ex);
    }
  }
}