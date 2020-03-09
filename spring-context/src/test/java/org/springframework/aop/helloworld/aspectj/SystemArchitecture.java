package org.springframework.aop.helloworld.aspectj;

import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;

@Aspect
public class SystemArchitecture {

	@Pointcut("execution(* org.springframework.aop.helloworld.*.*(..))")
	public void businessService() {}

//	@Pointcut("bean(*ServiceImpl)")
//	public void businessService() {}
}
