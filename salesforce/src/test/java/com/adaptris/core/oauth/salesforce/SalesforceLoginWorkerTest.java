package com.adaptris.core.oauth.salesforce;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Test;

import com.adaptris.core.CoreException;
import com.adaptris.core.http.oauth.AccessToken;

public class SalesforceLoginWorkerTest {

  private static final String ACCESS_TOKEN_WITH_TYPE = "{\"access_token\" : \"token\", \"token_type\" : \"Bearer\"}";
  private static final String ACCESS_TOKEN = "{\"access_token\" : \"token\"}";
  private static final String DUFF_JSON = "{\"blahblah\" : \"token\"}";

  @Before
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
    
    CloseableHttpResponse response = mock(CloseableHttpResponse.class);
    HttpEntity mockEntity = mock(HttpEntity.class);
    when(response.getEntity()).thenReturn(mockEntity);
    when(mockEntity.getContent()).thenReturn(IOUtils.toInputStream(ACCESS_TOKEN_WITH_TYPE));
    when(response.getEntity().getContent()).thenReturn(IOUtils.toInputStream(ACCESS_TOKEN_WITH_TYPE));
    final CloseableHttpClient client = mock(CloseableHttpClient.class);
    when(client.execute((HttpUriRequest) anyObject())).thenReturn(response);
    
    SalesforceLoginWorker worker = new SalesforceLoginWorker("http://localhost", "localhost:3128") {
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

    CloseableHttpResponse response = mock(CloseableHttpResponse.class);
    HttpEntity mockEntity = mock(HttpEntity.class);
    when(response.getEntity()).thenReturn(mockEntity);
    when(mockEntity.getContent()).thenReturn(IOUtils.toInputStream(ACCESS_TOKEN_WITH_TYPE));
    when(response.getEntity().getContent()).thenReturn(IOUtils.toInputStream(ACCESS_TOKEN_WITH_TYPE));
    final CloseableHttpClient client = mock(CloseableHttpClient.class);
    when(client.execute((HttpUriRequest) anyObject())).thenThrow(new IOException());

    SalesforceLoginWorker worker = new SalesforceLoginWorker("http://localhost", "localhost:3128") {
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
  public void testBuildToken_WithType() throws Exception {
    SalesforceLoginWorker worker = new SalesforceLoginWorker("http://localhost", "localhost:3128");
    HttpResponse response = mock(HttpResponse.class);
    HttpEntity mockEntity = mock(HttpEntity.class);
    when(response.getEntity()).thenReturn(mockEntity);
    when(mockEntity.getContent()).thenReturn(IOUtils.toInputStream(ACCESS_TOKEN_WITH_TYPE));
    when(response.getEntity().getContent()).thenReturn(IOUtils.toInputStream(ACCESS_TOKEN_WITH_TYPE));

    AccessToken token = worker.buildToken(response);

    assertEquals("token", token.getToken());
    assertEquals("Bearer", token.getType());
  }

  @Test
  public void testBuildToken_NoType() throws Exception {
    SalesforceLoginWorker worker = new SalesforceLoginWorker("http://localhost", "localhost:3128");
    HttpResponse response = mock(HttpResponse.class);
    HttpEntity mockEntity = mock(HttpEntity.class);
    when(response.getEntity()).thenReturn(mockEntity);
    when(mockEntity.getContent()).thenReturn(IOUtils.toInputStream(ACCESS_TOKEN));
    when(response.getEntity().getContent()).thenReturn(IOUtils.toInputStream(ACCESS_TOKEN));

    AccessToken token = worker.buildToken(response);

    assertEquals("token", token.getToken());
    assertEquals("Bearer", token.getType());
  }

  @Test
  public void testBuildToken_BadJson() throws Exception {
    SalesforceLoginWorker worker = new SalesforceLoginWorker("http://localhost", "localhost:3128");
    HttpResponse response = mock(HttpResponse.class);
    HttpEntity mockEntity = mock(HttpEntity.class);
    when(response.getEntity()).thenReturn(mockEntity);
    when(mockEntity.getContent()).thenReturn(IOUtils.toInputStream(DUFF_JSON));
    when(response.getEntity().getContent()).thenReturn(IOUtils.toInputStream(DUFF_JSON));

    try {
      AccessToken token = worker.buildToken(response);
      fail();
    }
    catch (NullPointerException expected) {
      
    }
  }

}
