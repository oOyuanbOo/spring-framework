package org.springframework.tests.sample.beans;

public class TestA {

	private TestB testB;

	TestA(TestB b){
		this.testB = b;
	}

	public void setTestB(TestB testB) {
		this.testB = testB;
	}
}
