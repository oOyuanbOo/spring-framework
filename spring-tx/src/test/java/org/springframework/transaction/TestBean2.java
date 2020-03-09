package org.springframework.transaction;

import org.springframework.tests.sample.beans.TestBean;
import org.springframework.transaction.annotation.Transactional;

public class TestBean2 extends TestBean {

	@Override
	@Transactional
	public Object returnsThis(){
		return super.returnsThis();
	}
}
