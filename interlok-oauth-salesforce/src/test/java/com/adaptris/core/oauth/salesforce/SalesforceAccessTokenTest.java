/*
    Copyright Adaptris Ltd.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

package com.adaptris.core.oauth.salesforce;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyObject;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.apache.http.HttpEntity;
import org.junit.Before;
import org.junit.Test;
import com.adaptris.core.AdaptrisMessageFactory;
import com.adaptris.core.CoreException;
import com.adaptris.core.http.oauth.AccessToken;
import com.adaptris.core.util.LifecycleHelper;

public class SalesforceAccessTokenTest {

  @Before
  public void setUp() throws Exception {

  }

  @Test
  public void testLifecycle() throws Exception {
    SalesforceAccessToken tokenBuilder = new SalesforceAccessToken();
    try {
      LifecycleHelper.init(tokenBuilder);
      fail();
    }
    catch (CoreException expected) {

    }
    tokenBuilder.setUsername("test");
    try {
      LifecycleHelper.init(tokenBuilder);
      fail();
    }
    catch (CoreException expected) {

    }
    tokenBuilder.setPassword("test");
    try {
      LifecycleHelper.init(tokenBuilder);
      fail();
    }
    catch (CoreException expected) {

    }
    tokenBuilder.setConsumerKey("test");
    try {
      LifecycleHelper.init(tokenBuilder);
      fail();
    }
    catch (CoreException expected) {

    }
    tokenBuilder.setConsumerSecret("test");
    LifecycleHelper.stopAndClose(LifecycleHelper.initAndStart(tokenBuilder));
  }

  @Test
  public void testConsumerKey() {
    SalesforceAccessToken tokenBuilder = new SalesforceAccessToken();
    assertNull(tokenBuilder.getConsumerKey());
    tokenBuilder.setConsumerKey("test");
    assertEquals("test", tokenBuilder.getConsumerKey());
    try {
      tokenBuilder.setConsumerKey(null);
      fail();
    }
    catch (IllegalArgumentException e) {

    }
    assertEquals("test", tokenBuilder.getConsumerKey());
  }

  @Test
  public void testConsumerSecret() {
    SalesforceAccessToken tokenBuilder = new SalesforceAccessToken();
    assertNull(tokenBuilder.getConsumerSecret());
    tokenBuilder.setConsumerSecret("test");
    assertEquals("test", tokenBuilder.getConsumerSecret());
    try {
      tokenBuilder.setConsumerSecret(null);
      fail();
    }
    catch (IllegalArgumentException e) {

    }
    assertEquals("test", tokenBuilder.getConsumerSecret());
  }

  @Test
  public void testUsername() {
    SalesforceAccessToken tokenBuilder = new SalesforceAccessToken();
    assertNull(tokenBuilder.getUsername());
    tokenBuilder.setUsername("test");
    assertEquals("test", tokenBuilder.getUsername());
    try {
      tokenBuilder.setUsername(null);
      fail();
    }
    catch (IllegalArgumentException e) {

    }
    assertEquals("test", tokenBuilder.getUsername());
  }

  @Test
  public void testPassword() {
    SalesforceAccessToken tokenBuilder = new SalesforceAccessToken();
    assertNull(tokenBuilder.getPassword());
    tokenBuilder.setPassword("test");
    assertEquals("test", tokenBuilder.getPassword());
    try {
      tokenBuilder.setPassword(null);
      fail();
    }
    catch (IllegalArgumentException e) {

    }
    assertEquals("test", tokenBuilder.getPassword());
  }

  @Test
  public void testProxy() {
    SalesforceAccessToken tokenBuilder = new SalesforceAccessToken();
    assertNull(tokenBuilder.getHttpProxy());
    tokenBuilder.setHttpProxy("test");
    assertEquals("test", tokenBuilder.getHttpProxy());
    tokenBuilder.setHttpProxy(null);
    assertNull(tokenBuilder.getHttpProxy());
  }

  @Test
  public void testTokenUrl() {
    SalesforceAccessToken tokenBuilder = new SalesforceAccessToken();
    assertNull(tokenBuilder.getTokenUrl());
    assertEquals(SalesforceAccessToken.DEFAULT_TOKEN_URL, tokenBuilder.tokenUrl());
    tokenBuilder.setTokenUrl("test");
    assertEquals("test", tokenBuilder.getTokenUrl());
    assertEquals("test", tokenBuilder.tokenUrl());
    tokenBuilder.setTokenUrl(null);
    assertEquals(SalesforceAccessToken.DEFAULT_TOKEN_URL, tokenBuilder.tokenUrl());
  }

  @Test
  public void testCreateWorker() {
    SalesforceAccessToken tokenBuilder = new SalesforceAccessToken();
    tokenBuilder.setUsername("test");
    tokenBuilder.setPassword("test");
    tokenBuilder.setConsumerKey("test");
    tokenBuilder.setConsumerSecret("test");
    assertNotNull(tokenBuilder.createWorker());
  }

  @Test
  public void testBuildToken() throws Exception {
    final SalesforceLoginWorker worker = mock(SalesforceLoginWorker.class);
    SalesforceAccessToken tokenBuilder = new SalesforceAccessToken() {
      @Override
      SalesforceLoginWorker createWorker() {
        return worker;
      }
    };
    tokenBuilder.setUsername("test");
    tokenBuilder.setPassword("test");
    tokenBuilder.setConsumerKey("test");
    tokenBuilder.setConsumerSecret("test");
    AccessToken myAccessToken = new AccessToken("Bearer", "token");
    when(worker.login((HttpEntity) anyObject())).thenReturn(myAccessToken);
    try {
      LifecycleHelper.initAndStart(tokenBuilder);
      AccessToken token = tokenBuilder.build(AdaptrisMessageFactory.getDefaultInstance().newMessage());
      assertEquals("token", token.getToken());
    } finally {
      LifecycleHelper.stopAndClose(tokenBuilder);
    }
  }

  @Test
  public void testBuildToken_PasswordException() throws Exception {
    final SalesforceLoginWorker worker = mock(SalesforceLoginWorker.class);
    SalesforceAccessToken tokenBuilder = new SalesforceAccessToken() {
      @Override
      SalesforceLoginWorker createWorker() {
        return worker;
      }
    };
    tokenBuilder.setUsername("test");
    tokenBuilder.setPassword("PW:test");
    tokenBuilder.setConsumerKey("test");
    tokenBuilder.setConsumerSecret("test");
    AccessToken myAccessToken = new AccessToken("Bearer", "token");
    when(worker.login((HttpEntity) anyObject())).thenReturn(myAccessToken);
    try {
      LifecycleHelper.initAndStart(tokenBuilder);
      AccessToken token = tokenBuilder.build(AdaptrisMessageFactory.getDefaultInstance().newMessage());
      fail();
    }
    catch (CoreException e) {

    }
    finally {
      LifecycleHelper.stopAndClose(tokenBuilder);
    }
  }
}
