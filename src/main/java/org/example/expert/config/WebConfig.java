package org.example.expert.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {

    // ArgumentResolver 등록
    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new AuthUserArgumentResolver());
    }

//    // 인터셉터 등록
//    public void addInterceptors(InterceptorRegistry registry){
//        registry.addInterceptor(new LogInterceptor())
//            .order(1)
//            .addPathPatterns("/**")
//            .excludePathPatterns(
//                "/auth/signup",
//                "/auth/login",
//                "/css/**",
//                "/*.ico",
//                "/error"
//            );
//    }
}
