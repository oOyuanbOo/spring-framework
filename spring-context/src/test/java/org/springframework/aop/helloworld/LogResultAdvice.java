package org.springframework.aop.helloworld;

import org.springframework.aop.AfterReturningAdvice;

import java.lang.reflect.Method;

public class LogResultAdvice implements AfterReturningAdvice {
	@Override
	public void afterReturning(Object returnValue, Method method, Object[] args, Object target) throws Throwable {
		System.out.println(method.getName() + " 方法返回： " + returnValue);
	}
}
