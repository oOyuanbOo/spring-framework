package org.springframework.aop.helloworld;

public interface UserService {

	User createUser(String username, String product);

	User queryUser(String username);
}
