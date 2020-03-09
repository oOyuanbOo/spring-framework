package org.springframework.aop.helloworld;

public class UserServceImpl implements UserService {
	@Override
	public User createUser(String firstName, String lastName) {
		User User = new User();
		User.setFirstName(firstName);
		User.setLastName(lastName);
		return User;
	}

	@Override
	public User queryUser(String username) {
		User User = new User();
		User.setFirstName("test");
		User.setLastName("test");
		return User;
	}
}
