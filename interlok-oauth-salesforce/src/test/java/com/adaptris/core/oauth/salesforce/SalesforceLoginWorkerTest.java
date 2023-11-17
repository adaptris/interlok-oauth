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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.adaptris.core.CoreException;
import com.adaptris.core.http.oauth.AccessToken;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.ProtocolVersion;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicStatusLine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("deprecation")
public class SalesforceLoginWorkerTest {

  private static final String ACCESS_TOKEN_WITH_TYPE = "{\"access_token\" : \"token\", \"token_type\" : \"Bearer\"}";
  private static final String ACCESS_TOKEN = "{\"access_token\" : \"token\"}";
  private static final String DUFF_JSON = "{\"blahblah\" : \"token\"}";

  @BeforeEach
  public void setUp() throws Exception {

  }

  @Test
  public void testCreateClient() throws Exception {
    assertNotNull(new SalesforceLoginWorker("http://localhost", "localhost:3128").createClient());
    assertNotNull(new SalesforceLoginWorker("http://localhost", null).createClient());
    assertNotNull(new SalesforceLoginWorker("http://localhost", ":").createClient());
  }

  @Test
  public void testLogin() throws Exception {
    
    HttpEntity mockEntity = mock(HttpEntity.class);
    final CloseableHttpClient client = mock(CloseableHttpClient.class);
    when(client.execute((HttpUriRequest) any(), (ResponseHandler) any())).thenReturn(ACCESS_TOKEN_WITH_TYPE);
    
    SalesforceLoginWorker worker = new SalesforceLoginWorker("http://localhost", "localhost:3128") {
      @Override
      CloseableHttpClient createClient() {
        return client;
      }
    };
    AccessToken token = worker.login(mockEntity);
    assertEquals("token", token.getToken());
    assertEquals("Bearer", token.getType());
  }

  @Test
  public void testLogin_Error() throws Exception {

    HttpEntity mockEntity = mock(HttpEntity.class);
    final CloseableHttpClient client = mock(CloseableHttpClient.class);
    when(client.execute((HttpUriRequest) any(), (ResponseHandler) any()))
        .thenThrow(new HttpResponseException(400, "Bad Request"));

    SalesforceLoginWorker worker = new SalesforceLoginWorker("http://localhost", "localhost:3128") {
      @Override
      CloseableHttpClient createClient() {
        return client;
      }
    };
    try {
      AccessToken token = worker.login(mockEntity);
      fail();
    }
    catch (CoreException expected) {

    }
  }

  @Test
  public void testLogin_ErrorResponse() throws Exception {

    HttpEntity mockEntity = mock(HttpEntity.class);
    final CloseableHttpClient client = mock(CloseableHttpClient.class);
    when(client.execute((HttpUriRequest) any(), (ResponseHandler) any())).thenReturn(DUFF_JSON);


    SalesforceLoginWorker worker = new SalesforceLoginWorker("http://localhost", "localhost:3128") {
      @Override
      CloseableHttpClient createClient() {
        return client;
      }
    };
    try {
      AccessToken token = worker.login(mockEntity);
      fail();
    } catch (CoreException expected) {

    }
  }


  @Test
  public void testBuildToken_WithType() throws Exception {
    SalesforceLoginWorker worker = new SalesforceLoginWorker("http://localhost", "localhost:3128");
    AccessToken token = worker.buildToken(ACCESS_TOKEN_WITH_TYPE);
    assertEquals("token", token.getToken());
    assertEquals("Bearer", token.getType());
  }

  @Test
  public void testBuildToken_NoType() throws Exception {
    SalesforceLoginWorker worker = new SalesforceLoginWorker("http://localhost", "localhost:3128");
    AccessToken token = worker.buildToken(ACCESS_TOKEN);
    assertEquals("token", token.getToken());
    assertEquals("Bearer", token.getType());
  }

  @Test
  public void testBuildToken_BadJson() throws Exception {
    SalesforceLoginWorker worker = new SalesforceLoginWorker("http://localhost", "localhost:3128");
    try {
      AccessToken token = worker.buildToken(DUFF_JSON);
      fail();
    }
    catch (NullPointerException expected) {
      
    }
  }


  @Test
  public void testCustomResponseHandler() throws Exception {
    BasicStatusLine status = new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), HttpStatus.SC_OK, "OK");
    CloseableHttpResponse response = mock(CloseableHttpResponse.class);
    HttpEntity mockEntity = mock(HttpEntity.class);
    when(response.getEntity()).thenReturn(mockEntity);
    when(mockEntity.getContent()).thenReturn(IOUtils.toInputStream(ACCESS_TOKEN_WITH_TYPE));
    when(response.getStatusLine()).thenReturn(status);


    SalesforceLoginWorker.CustomResponseHandler handler = new SalesforceLoginWorker.CustomResponseHandler();
    assertEquals(ACCESS_TOKEN_WITH_TYPE, handler.handleResponse(response));
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
    when(mockEntity.getContent()).thenReturn(IOUtils.toInputStream(ACCESS_TOKEN_WITH_TYPE));
    when(response.getStatusLine()).thenReturn(status);

    SalesforceLoginWorker.CustomResponseHandler handler = new SalesforceLoginWorker.CustomResponseHandler();
    assertEquals(ACCESS_TOKEN_WITH_TYPE, handler.handleResponse(response));
    assertNotNull(handler.statusLine());
    assertTrue(handler.statusLine().contains("HTTP/1.1"));
    assertThrows(HttpResponseException.class, ()->{
      handler.throwExceptionIfAny();
    }, "Failed with non 2xx response code.");
  }
  

}
