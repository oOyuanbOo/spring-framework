package org.springframework.aop.helloworld.aspectj;

import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.aop.AfterReturningAdvice;

import java.lang.reflect.Method;

@Aspect
public class LogResultAdviceWithAnnotation{
	@AfterReturning(value = "org.springframework.aop.helloworld.aspectj.SystemArchitecture.businessService()", returning = "result")
	public void afterReturning(Object result) throws Throwable {
		System.out.println(" 方法返回： " + result);
	}
}
