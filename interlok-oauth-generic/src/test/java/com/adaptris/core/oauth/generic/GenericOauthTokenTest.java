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

package com.adaptris.core.oauth.generic;

import static com.adaptris.core.oauth.generic.JsonResponseHandlerTest.ACCESS_TOKEN;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.AdaptrisMessageFactory;
import com.adaptris.core.CoreException;
import com.adaptris.core.ServiceCase;
import com.adaptris.core.ServiceException;
import com.adaptris.core.http.apache.HttpClientBuilderConfigurator;
import com.adaptris.core.http.oauth.GetOauthToken;
import com.adaptris.core.metadata.NoOpMetadataFilter;
import com.adaptris.core.util.LifecycleHelper;

public class GenericOauthTokenTest extends ServiceCase {

  public GenericOauthTokenTest(String s) {
    super(s);
  }

  @Override
  protected Object retrieveObjectForSampleConfig() {
    GetOauthToken service = new GetOauthToken();
    service.setAccessTokenBuilder(
        new GenericAccessToken().withResponseHandler(new JsonResponseHandler()).withTokenUrl("http://my-oauth-server.com/oauth"));
    return service;
  }

  public void testLifecycle() throws Exception {
    GetOauthToken service = new GetOauthToken();
    GenericAccessToken tokenBuilder = new GenericAccessToken();
    service.setAccessTokenBuilder(tokenBuilder);
    try {
      LifecycleHelper.initAndStart(service);
      fail();
    } catch (CoreException expected) {

    }
    tokenBuilder.withTokenUrl("http://localhost:1234").withResponseHandler(new JsonResponseHandler());
    try {
      LifecycleHelper.initAndStart(service);
    } finally {
      LifecycleHelper.stopAndClose(service);
    }
  }

  public void testLogin() throws Exception {
    GetOauthToken service = new GetOauthToken();
    service.setAccessTokenBuilder(new GenericAccessToken().withResponseHandler(new JsonResponseHandler())
        .withTokenUrl("http://localhost:1234").withClientConfig(new MyHttpClientBuilderConfigurator(ACCESS_TOKEN, false))
        .withMetadataFilter(new NoOpMetadataFilter()));
    try {
      LifecycleHelper.initAndStart(service);
      AdaptrisMessage msg = AdaptrisMessageFactory.getDefaultInstance().newMessage();
      msg.addMessageHeader("hello", "world");
      service.doService(msg);
      String bearerToken = "Bearer token";
      assertEquals(bearerToken, msg.getMetadataValue("Authorization"));
    } finally {
      LifecycleHelper.stopAndClose(service);
    }
  }

  public void testLogin_WithError() throws Exception {
    GetOauthToken service = new GetOauthToken();
    service.setAccessTokenBuilder(new GenericAccessToken().withResponseHandler(new JsonResponseHandler())
        .withTokenUrl("http://localhost:1234").withClientConfig(new MyHttpClientBuilderConfigurator(ACCESS_TOKEN, true)));
    try {
      LifecycleHelper.initAndStart(service);
      AdaptrisMessage msg = AdaptrisMessageFactory.getDefaultInstance().newMessage();
      service.doService(msg);
      fail();
    } catch (ServiceException expected) {

    } finally {
      LifecycleHelper.stopAndClose(service);
    }
  }

  private class MyHttpClientBuilderConfigurator implements HttpClientBuilderConfigurator {
    HttpClientBuilder mockBuilder;


    MyHttpClientBuilderConfigurator(String responseContent, boolean hasError) throws Exception {
      CloseableHttpResponse response = mock(CloseableHttpResponse.class);
      HttpEntity mockEntity = mock(HttpEntity.class);
      when(response.getEntity()).thenReturn(mockEntity);
      when(mockEntity.getContent()).thenReturn(IOUtils.toInputStream(responseContent));
      when(response.getEntity().getContent()).thenReturn(IOUtils.toInputStream(responseContent));
      CloseableHttpClient client = mock(CloseableHttpClient.class);
      if (hasError) {
        when(client.execute((HttpUriRequest) anyObject())).thenThrow(new IOException());
      } else {
        when(client.execute((HttpUriRequest) anyObject())).thenReturn(response);
      }
      mockBuilder = mock(HttpClientBuilder.class);
      when(mockBuilder.build()).thenReturn(client);
    }

    @Override
    public HttpClientBuilder configure(HttpClientBuilder builder) throws Exception {
      return mockBuilder;
    }

  }
}
