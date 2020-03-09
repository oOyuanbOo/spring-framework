package org.springframework.tests.sample.beans;

public class TestB {
	private TestA testA;

	TestB(TestA a){
		this.testA = a;
	}

	public void setTestA(TestA testA) {
		this.testA = testA;
	}
}
