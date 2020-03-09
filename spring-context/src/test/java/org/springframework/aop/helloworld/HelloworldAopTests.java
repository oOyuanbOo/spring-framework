package org.springframework.aop.helloworld;


import org.junit.jupiter.api.Test;
import org.springframework.context.support.ClassPathXmlApplicationContext;

public class HelloworldAopTests {
	@Test
	public void testAdvice(){
		// 启动容器
		// 1. 只配置advice，粗粒度，target类里面的方法都会被拦截
//		ClassPathXmlApplicationContext ctx = new ClassPathXmlApplicationContext("helloworld-aop.xml", this.getClass());
		// 2. 配置advisor，细粒度，配置mappedMethod拦截指定方法
		ClassPathXmlApplicationContext ctx = new ClassPathXmlApplicationContext("helloworld-aop-to-method-autoProxy-autoFindAdvisor.xml", this.getClass());

		// 我们这里获取AOP代理： userServiceProxy，这非常重要
		UserService userService = ctx.getBean(UserService.class);

		userService.createUser("yuanbo", "booo");
		userService.queryUser("yuansiyuan");

	}

	@Test
	public void testAutoProxy(){

		String xml = "helloworld-aop-to-method-autoProxy-autoFindAdvisor.xml";

		getBeanThenInvokeMethod(xml);
	}


	@Test
	public void testAutoProxyWithAnnotaion(){

		String xml = "helloworld-aop-annotation.xml";

		getBeanThenInvokeMethod(xml);

	}

	@Test
	public void testAutoProxyWithSchemaBased(){
		String xml = "helloworld-aop-schema-based.xml";

		getBeanThenInvokeMethod(xml);

	}

	private void getBeanThenInvokeMethod(String xml){
		ClassPathXmlApplicationContext ctx = new ClassPathXmlApplicationContext(xml, this.getClass());

		// 这里就不需要获取代理bean了
		UserService userService = ctx.getBean(UserService.class);
		OrderService orderService = ctx.getBean(OrderService.class);

		userService.createUser("yuanbo", "booo");
		userService.queryUser("yuansiyuan");

		orderService.createOrder("yuanbo", "booo");
		orderService.queryOrder("yuansiyuan");
	}
}

