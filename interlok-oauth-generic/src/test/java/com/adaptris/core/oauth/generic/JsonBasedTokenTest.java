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
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.AdaptrisMessageFactory;
import com.adaptris.core.http.oauth.GetOauthToken;
import com.adaptris.core.metadata.RegexMetadataFilter;
import com.adaptris.core.oauth.generic.GenericAccessTokenImplTest.MyHttpClientBuilderConfigurator;
import com.adaptris.core.util.LifecycleHelper;
import com.adaptris.interlok.junit.scaffolding.services.ExampleServiceCase;

public class JsonBasedTokenTest extends ExampleServiceCase {

  @Override
  protected Object retrieveObjectForSampleConfig() {
    GetOauthToken service = new GetOauthToken();
    service.setAccessTokenBuilder(
        new JsonBasedAccessToken().withResponseHandler(new JsonResponseHandler())
            .withTokenUrl("http://my-oauth-server.com/oauth"));
    return service;
  }

  @Test
  public void testLogin() throws Exception {
    GetOauthToken service = new GetOauthToken();
    service.setAccessTokenBuilder(new JsonBasedAccessToken()
        .withContentBuilder(new RegexMetadataFilter().withIncludePatterns("password"))
        .withResponseHandler(new JsonResponseHandler())
            .withTokenUrl("http://localhost:1234")
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
}
