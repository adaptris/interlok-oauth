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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.ProtocolVersion;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicStatusLine;
import org.junit.jupiter.api.Test;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.AdaptrisMessageFactory;
import com.adaptris.core.CoreConstants;
import com.adaptris.core.CoreException;
import com.adaptris.core.MetadataCollection;
import com.adaptris.core.http.apache.HttpClientBuilderConfigurator;
import com.adaptris.core.http.oauth.AccessToken;
import com.adaptris.core.util.LifecycleHelper;

@SuppressWarnings("deprecation")
public class GenericAccessTokenImplTest extends FormBasedAccessToken {

  @Test
  public void testLogin() throws Exception {
    GenericAccessTokenImpl tokenBuilder = this;
    try {
      LifecycleHelper.initAndStart(tokenBuilder);
      AdaptrisMessage msg = AdaptrisMessageFactory.getDefaultInstance().newMessage();
      msg.addMessageHeader(CoreConstants.HTTP_PRODUCER_RESPONSE_CODE, "-1");
      msg.addMessageHeader("password", "MyPassword");
      msg.addMessageHeader("client_id", "MyClientId");
      AccessToken token = tokenBuilder.build(msg);
      assertEquals("token", token.getToken());
      assertEquals("Bearer", token.getType());
      assertEquals("200", msg.getMetadataValue(CoreConstants.HTTP_PRODUCER_RESPONSE_CODE));
    } finally {
      LifecycleHelper.stopAndClose(tokenBuilder);
    }
  }

  @Test
  public void testCustomResponseHandler() throws Exception {
    BasicStatusLine status = new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), HttpStatus.SC_OK, "OK");
    CloseableHttpResponse response = mock(CloseableHttpResponse.class);
    HttpEntity mockEntity = mock(HttpEntity.class);
    when(response.getEntity()).thenReturn(mockEntity);
    when(mockEntity.getContent()).thenReturn(IOUtils.toInputStream(ACCESS_TOKEN));
    when(response.getStatusLine()).thenReturn(status);


    CustomResponseHandler handler = new CustomResponseHandler((i) -> {
    });
    assertEquals(ACCESS_TOKEN, handler.handleResponse(response));
    assertNotNull(handler.statusLine());
    assertTrue(handler.statusLine().contains("HTTP/1.1"));
    handler.throwExceptionIfAny();
  }

  @Test
  public void testCustomResponseHandler_NotFound() throws Exception {
    BasicStatusLine status = new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), HttpStatus.SC_NOT_FOUND, "Not Found");
    CloseableHttpResponse response = mock(CloseableHttpResponse.class);
    HttpEntity mockEntity = mock(HttpEntity.class);
    when(response.getEntity()).thenReturn(mockEntity);
    when(mockEntity.getContent()).thenReturn(IOUtils.toInputStream(ACCESS_TOKEN));
    when(response.getStatusLine()).thenReturn(status);
    final AtomicInteger httpStatus = new AtomicInteger(1);
    try {
      CustomResponseHandler handler = new CustomResponseHandler((i) -> httpStatus.set(i));
      assertEquals(ACCESS_TOKEN, handler.handleResponse(response));
      assertNotNull(handler.statusLine());
      assertTrue(handler.statusLine().contains("HTTP/1.1"));
      handler.throwExceptionIfAny();
      fail();
    } catch (HttpResponseException expected) {
      assertEquals(HttpStatus.SC_NOT_FOUND, httpStatus.get());
    }
  }

  @Override
  protected AccessToken login(String url, HttpEntity entity, MetadataCollection httpHeaders,
      Consumer<Integer> httpStatusCallback) {
    AccessToken token = new AccessToken("token");
    Optional.ofNullable(httpStatusCallback).ifPresent((c) -> c.accept(200));
    return new AccessToken("token");
  }

  // To fake it out, since we never call getResponseHandler()
  @Override
  public void init() throws CoreException {
    LifecycleHelper.init(getResponseHandler());
  }

  public static class MyHttpClientBuilderConfigurator implements HttpClientBuilderConfigurator {
    HttpClientBuilder mockBuilder;


    MyHttpClientBuilderConfigurator(String responseContent, boolean hasError) throws Exception {
      CloseableHttpResponse response = mock(CloseableHttpResponse.class);
      HttpEntity mockEntity = mock(HttpEntity.class);
      when(response.getEntity()).thenReturn(mockEntity);
      when(mockEntity.getContent()).thenReturn(IOUtils.toInputStream(responseContent, Charset.defaultCharset()));
      when(response.getEntity().getContent()).thenReturn(IOUtils.toInputStream(responseContent,Charset.defaultCharset()));
      CloseableHttpClient client = mock(CloseableHttpClient.class);
      if (hasError) {
        when(client.execute((HttpUriRequest) any())).thenThrow(new IOException());
        when(client.execute((HttpUriRequest) any(), (ResponseHandler) any())).thenThrow(new IOException());

      } else {
        when(client.execute((HttpUriRequest) any())).thenReturn(response);
        when(client.execute((HttpUriRequest) any(), (ResponseHandler) any()))
            .thenReturn(responseContent);
      }
      mockBuilder = mock(HttpClientBuilder.class);
      when(mockBuilder.build()).thenReturn(client);
      when(mockBuilder.useSystemProperties()).thenReturn(mockBuilder);
    }

    @Override
    public HttpClientBuilder configure(HttpClientBuilder builder) throws Exception {
      return mockBuilder;
    }

  }


}
