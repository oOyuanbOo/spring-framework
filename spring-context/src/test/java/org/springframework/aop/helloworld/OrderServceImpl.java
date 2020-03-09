package org.springframework.aop.helloworld;

public class OrderServceImpl implements OrderService {
	@Override
	public Order createOrder(String username, String product) {
		Order order = new Order();
		order.setProduct(product);
		order.setUsername(username);
		return order;
	}

	@Override
	public Order queryOrder(String username) {
		Order order = new Order();
		order.setUsername("test");
		order.setProduct("test");
		return order;
	}
}
