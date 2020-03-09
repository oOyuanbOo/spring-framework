package org.springframework.aop.helloworld.aspectj;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.aop.MethodBeforeAdvice;

import java.lang.reflect.Method;
import java.util.Arrays;

@Aspect
public class LogArgsAdviceWithAnnotation{

	@Before("org.springframework.aop.helloworld.aspectj.SystemArchitecture.businessService()")
	public void before(JoinPoint joinPoint) throws Throwable {
		System.out.println("参数列表：" + Arrays.toString(joinPoint.getArgs()));
	}
}
