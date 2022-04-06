package com.chilly.config;

import com.chilly.interceptors.JWTInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Created by
 */
@Configuration
public class InterceptorConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new JWTInterceptor())
//                进行拦截，一般登录不拦截，企业都拦截
                .addPathPatterns("/user/**")
                .excludePathPatterns("/user/login")
        ;
    }
}
