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
import static org.junit.jupiter.api.Assertions.fail;
import org.junit.jupiter.api.Test;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.AdaptrisMessageFactory;
import com.adaptris.core.ServiceException;
import com.adaptris.core.http.oauth.GetOauthToken;
import com.adaptris.core.metadata.NoOpMetadataFilter;
import com.adaptris.core.metadata.RegexMetadataFilter;
import com.adaptris.core.oauth.generic.GenericAccessTokenImplTest.MyHttpClientBuilderConfigurator;
import com.adaptris.core.util.LifecycleHelper;
import com.adaptris.interlok.junit.scaffolding.services.ExampleServiceCase;

@SuppressWarnings("deprecation")
public class FormBasedAccessTokenTest extends ExampleServiceCase {

  @Override
  protected Object retrieveObjectForSampleConfig() {
    GetOauthToken service = new GetOauthToken();
    service.setAccessTokenBuilder(
        new FormBasedAccessToken()
            .withFormBuilder(
                new RegexMetadataFilter()
                    .withIncludePatterns(GenericAccessTokenImpl.DEFAULT_METADATA_PATTERNS))
            .withResponseHandler(new JsonResponseHandler())
            .withTokenUrl("http://my-oauth-server.com/oauth"));
    return service;
  }

  @Test
  public void testLifecycle() throws Exception {
    GetOauthToken service = new GetOauthToken();
    FormBasedAccessToken tokenBuilder = new FormBasedAccessToken();
    tokenBuilder.withTokenUrl("http://localhost:1234")
        .withResponseHandler(new JsonResponseHandler());
    service.setAccessTokenBuilder(tokenBuilder);
    try {
      LifecycleHelper.initAndStart(service);
    } finally {
      LifecycleHelper.stopAndClose(service);
    }
  }

  @Test
  public void testLogin() throws Exception {
    GetOauthToken service = new GetOauthToken();
    service.setAccessTokenBuilder(new FormBasedAccessToken()
        .withResponseHandler(new JsonResponseHandler())
            .withTokenUrl("http://localhost:1234")
            .withAdditionalHeaders(new NoOpMetadataFilter())
            .withClientConfig(new MyHttpClientBuilderConfigurator(ACCESS_TOKEN, false)));
    try {
      LifecycleHelper.initAndStart(service);
      AdaptrisMessage msg = AdaptrisMessageFactory.getDefaultInstance().newMessage();
      msg.addMessageHeader("hello", "world");
      msg.addMessageHeader("password", "MyPassword");
      msg.addMessageHeader("client_id", "MyClientId");
      service.doService(msg);
      String bearerToken = "Bearer token";
      assertEquals(bearerToken, msg.getMetadataValue("Authorization"));
    } finally {
      LifecycleHelper.stopAndClose(service);
    }
  }


  @Test
  public void testLogin_WithError() throws Exception {
    GetOauthToken service = new GetOauthToken();
    service
        .setAccessTokenBuilder(new FormBasedAccessToken()
        .withResponseHandler(new JsonResponseHandler()).withTokenUrl("http://localhost:1234")
            .withClientConfig(new MyHttpClientBuilderConfigurator(ACCESS_TOKEN, true)));
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
}
