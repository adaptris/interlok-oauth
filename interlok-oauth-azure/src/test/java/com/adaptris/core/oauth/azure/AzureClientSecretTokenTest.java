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

package com.adaptris.core.oauth.azure;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.concurrent.Future;

import org.junit.Before;
import org.junit.Test;

import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.AdaptrisMessageFactory;
import com.adaptris.core.CoreException;
import com.adaptris.core.http.oauth.AccessToken;
import com.adaptris.core.util.LifecycleHelper;
import com.microsoft.aad.adal4j.AuthenticationCallback;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;

public class AzureClientSecretTokenTest {

  @Before
  public void setUp() throws Exception {

  }

  @Test
  public void testLifecycle() throws Exception {
    AzureClientSecretAccessToken tokenBuilder = new AzureClientSecretAccessToken();
    try {
      LifecycleHelper.init(tokenBuilder);
      fail();
    }
    catch (CoreException expected) {

    }
    tokenBuilder.withClientSecret("test");
    tokenBuilder.withClientId("1234");
    tokenBuilder.withResource("https://graph.microsoft.com");
    LifecycleHelper.stopAndClose(LifecycleHelper.initAndStart(tokenBuilder));
  }

  @Test
  public void testBuildToken() throws Exception {
    final AuthenticationContext context = mock(AuthenticationContext.class);
    AuthenticationResult myAccessToken = new AuthenticationResult("Bearer", "accessToken", "refreshToken",
        System.currentTimeMillis(), "idToken", null, true);
    Future<AuthenticationResult> mockFuture = mock(Future.class);
    when(mockFuture.get()).thenReturn(myAccessToken);
    when(context.acquireToken(anyString(), (ClientCredential) any(), (AuthenticationCallback) any()))
        .thenReturn(mockFuture);

    AzureClientSecretAccessToken tokenBuilder = new AzureClientSecretAccessToken() {
      @Override
      protected AuthenticationContext authenticationContext(AdaptrisMessage msg) {
        return context;
      }
    };
    tokenBuilder.withClientSecret("test");
    tokenBuilder.withClientId("test");
    tokenBuilder.withResource("test");
    try {
      LifecycleHelper.initAndStart(tokenBuilder);
      AccessToken token = tokenBuilder.build(AdaptrisMessageFactory.getDefaultInstance().newMessage());
      assertEquals("accessToken", token.getToken());
      assertEquals("Bearer", token.getType());
      assertNotNull(token.getExpiry());
    } finally {
      LifecycleHelper.stopAndClose(tokenBuilder);
    }
  }

  @Test
  public void testBuildToken_Failure() throws Exception {
    final AuthenticationContext context = mock(AuthenticationContext.class);
    Future<AuthenticationResult> mockFuture = mock(Future.class);
    when(mockFuture.get()).thenReturn(null);
    when(context.acquireToken(anyString(), (ClientCredential) any(), (AuthenticationCallback) any()))
        .thenReturn(mockFuture);

    AzureClientSecretAccessToken tokenBuilder = new AzureClientSecretAccessToken() {
      @Override
      protected AuthenticationContext authenticationContext(AdaptrisMessage msg) {
        return context;
      }
    };
    tokenBuilder.withClientSecret("test");
    tokenBuilder.withClientId("test");
    tokenBuilder.withResource("test");
    try {
      LifecycleHelper.initAndStart(tokenBuilder);
      AccessToken token = tokenBuilder.build(AdaptrisMessageFactory.getDefaultInstance().newMessage());
      fail();
    }
    catch (IOException | CoreException expected) {

    }
    finally {
      LifecycleHelper.stopAndClose(tokenBuilder);
    }
  }
}
