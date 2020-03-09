package org.springframework.aop.helloworld;

public interface OrderService {

	Order createOrder(String username, String product);

	Order queryOrder(String username);
}
