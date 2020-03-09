/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.beans.factory.xml;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.xml.sax.InputSource;

import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.SimpleBeanDefinitionRegistry;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.tests.sample.beans.TestBean;
import org.springframework.util.ObjectUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Rick Evans
 * @author Juergen Hoeller
 * @author Sam Brannen
 */
public class XmlBeanDefinitionReaderTests {

	@Test
	public void letIoCstart() {
		// 根据xml配置文件创建Resource资源对象
		ClassPathResource resource = new ClassPathResource("testCircle.xml", getClass());
//		ClassPathResource resource = new ClassPathResource("test.xml", getClass());

		// 创建一个BeanFactory，DefaultListable是整个IoC的始祖
		DefaultListableBeanFactory factory = new DefaultListableBeanFactory();
		// 创建XmlBeanDefinitionReader读取器，用于载入BeanDefinition
		XmlBeanDefinitionReader reader = new XmlBeanDefinitionReader(factory);
		// 开始BeanDefinition的载入和注册过程，完成后的BeanDefinition放在IoC容器中
		reader.loadBeanDefinitions(resource);
		factory.getBean("testA");
//		factory.getBean("testA");
	}


	@Test
	public void setParserClassSunnyDay() {
		SimpleBeanDefinitionRegistry registry = new SimpleBeanDefinitionRegistry();
		new XmlBeanDefinitionReader(registry).setDocumentReaderClass(DefaultBeanDefinitionDocumentReader.class);
	}

	@Test
	public void withOpenInputStream() {
		SimpleBeanDefinitionRegistry registry = new SimpleBeanDefinitionRegistry();
		Resource resource = new InputStreamResource(getClass().getResourceAsStream("test.xml"));
		assertThatExceptionOfType(BeanDefinitionStoreException.class).isThrownBy(() ->
				new XmlBeanDefinitionReader(registry).loadBeanDefinitions(resource));
	}

	@Test
	public void withOpenInputStreamAndExplicitValidationMode() {
		SimpleBeanDefinitionRegistry registry = new SimpleBeanDefinitionRegistry();
		Resource resource = new InputStreamResource(getClass().getResourceAsStream("test.xml"));
		XmlBeanDefinitionReader reader = new XmlBeanDefinitionReader(registry);
		reader.setValidationMode(XmlBeanDefinitionReader.VALIDATION_DTD);
		reader.loadBeanDefinitions(resource);
		testBeanDefinitions(registry);
	}

	@Test
	public void withImport() {
		SimpleBeanDefinitionRegistry registry = new SimpleBeanDefinitionRegistry();
		Resource resource = new ClassPathResource("import.xml", getClass());
		new XmlBeanDefinitionReader(registry).loadBeanDefinitions(resource);
		testBeanDefinitions(registry);
	}

	@Test
	public void withWildcardImport() {
		SimpleBeanDefinitionRegistry registry = new SimpleBeanDefinitionRegistry();
		Resource resource = new ClassPathResource("importPattern.xml", getClass());
		new XmlBeanDefinitionReader(registry).loadBeanDefinitions(resource);
		testBeanDefinitions(registry);
	}

	@Test
	public void withInputSource() {
		SimpleBeanDefinitionRegistry registry = new SimpleBeanDefinitionRegistry();
		InputSource resource = new InputSource(getClass().getResourceAsStream("test.xml"));
		assertThatExceptionOfType(BeanDefinitionStoreException.class).isThrownBy(() ->
				new XmlBeanDefinitionReader(registry).loadBeanDefinitions(resource));
	}

	@Test
	public void withInputSourceAndExplicitValidationMode() {
		SimpleBeanDefinitionRegistry registry = new SimpleBeanDefinitionRegistry();
		InputSource resource = new InputSource(getClass().getResourceAsStream("test.xml"));
		XmlBeanDefinitionReader reader = new XmlBeanDefinitionReader(registry);
		reader.setValidationMode(XmlBeanDefinitionReader.VALIDATION_DTD);
		reader.loadBeanDefinitions(resource);
		testBeanDefinitions(registry);
	}

	@Test
	public void withFreshInputStream() {
		SimpleBeanDefinitionRegistry registry = new SimpleBeanDefinitionRegistry();
		Resource resource = new ClassPathResource("test.xml", getClass());
		new XmlBeanDefinitionReader(registry).loadBeanDefinitions(resource);
		testBeanDefinitions(registry);
	}

	private void testBeanDefinitions(BeanDefinitionRegistry registry) {
		assertThat(registry.getBeanDefinitionCount()).isEqualTo(24);
		assertThat(registry.getBeanDefinitionNames().length).isEqualTo(24);
		assertThat(Arrays.asList(registry.getBeanDefinitionNames()).contains("rod")).isTrue();
		assertThat(Arrays.asList(registry.getBeanDefinitionNames()).contains("aliased")).isTrue();
		assertThat(registry.containsBeanDefinition("rod")).isTrue();
		assertThat(registry.containsBeanDefinition("aliased")).isTrue();
		assertThat(registry.getBeanDefinition("rod").getBeanClassName()).isEqualTo(TestBean.class.getName());
		assertThat(registry.getBeanDefinition("aliased").getBeanClassName()).isEqualTo(TestBean.class.getName());
		assertThat(registry.isAlias("youralias")).isTrue();
		String[] aliases = registry.getAliases("aliased");
		assertThat(aliases.length).isEqualTo(2);
		assertThat(ObjectUtils.containsElement(aliases, "myalias")).isTrue();
		assertThat(ObjectUtils.containsElement(aliases, "youralias")).isTrue();
	}

	@Test
	public void dtdValidationAutodetect() {
		doTestValidation("validateWithDtd.xml");
	}

	@Test
	public void xsdValidationAutodetect() {
		doTestValidation("validateWithXsd.xml");
	}

	private void doTestValidation(String resourceName) {
		DefaultListableBeanFactory factory = new DefaultListableBeanFactory();
		Resource resource = new ClassPathResource(resourceName, getClass());
		new XmlBeanDefinitionReader(factory).loadBeanDefinitions(resource);
		TestBean bean = (TestBean) factory.getBean("testBean");
		assertThat(bean).isNotNull();
	}

}
