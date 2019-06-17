/*
 * Copyright 2019 Adaptris Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.adaptris.core.oauth.rfc5849;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import java.net.URL;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.AdaptrisMessageFactory;
import com.adaptris.core.oauth.rfc5849.AuthorizationData.SignatureMethod;

public class OauthAuthorizationBuilderTest {

  @Test
  public void testSignatureMethodDigest() throws Exception {
    for (SignatureMethod m : SignatureMethod.values()) {
      assertNotNull(m.digest("key", "value"));
      assertNotNull(m.formalName());
    }
  }

  @Test
  public void testBuild() throws Exception {
    AuthorizationData data = new AuthorizationData();
    AdaptrisMessage msg = AdaptrisMessageFactory.getDefaultInstance().newMessage();
    data.setAccessToken("accessToken");
    data.setConsumerKey("consumerKey");
    data.setConsumerSecret("consumerSecret");
    data.setTokenSecret("tokenSecret");
    AuthorizationBuilder builder = data.builder("POST", new URL("http://localhost"), msg);
    String authString = builder.build();
    assertNotNull(authString);
    assertTrue(authString.startsWith("OAuth"));
    System.out.println(authString);
    Map<String, String> params = unsplitAuthorization(authString.replace("OAuth ", ""));
    assertEquals(StringUtils.wrap("accessToken", '"'), params.get("oauth_token"));
    assertEquals(StringUtils.wrap("consumerKey", '"'), params.get("oauth_consumer_key"));
    assertEquals(StringUtils.wrap("1.0", '"'), params.get("oauth_version"));
    assertNotNull(params.get("oauth_timestamp"));
  }

  @Test
  public void testBuild_IncludeEmpty() throws Exception {
    AuthorizationData data = new AuthorizationData();
    AdaptrisMessage msg = AdaptrisMessageFactory.getDefaultInstance().newMessage();
    data.setAccessToken("accessToken");
    data.setConsumerKey("consumerKey");
    data.setConsumerSecret("consumerSecret");
    data.setTokenSecret("tokenSecret");
    data.setIncludeEmptyParams(true);
    AuthorizationBuilder builder =
        data.builder("POST", new URL("http://host/path?a=b&c=d"), msg);
    String authString = builder.build();
    assertNotNull(authString);
    assertTrue(authString.startsWith("OAuth"));
    System.out.println(authString);
    Map<String, String> params = unsplitAuthorization(authString.replace("OAuth ", ""));
    System.out.println(params);
    assertEquals(StringUtils.wrap("accessToken", '"'), params.get("oauth_token"));
    assertEquals(StringUtils.wrap("consumerKey", '"'), params.get("oauth_consumer_key"));
    assertEquals(StringUtils.wrap("1.0", '"'), params.get("oauth_version"));
    assertNotNull(params.get("oauth_timestamp"));
    assertEquals("\"\"", params.get("oauth_verifier"));
  }

  @Test
  public void testBuild_NoAccessToken() throws Exception {
    AuthorizationData data = new AuthorizationData();
    AdaptrisMessage msg = AdaptrisMessageFactory.getDefaultInstance().newMessage();
    data.setConsumerKey("consumerKey");
    data.setConsumerSecret("consumerSecret");
    AuthorizationBuilder builder = data.builder("POST", new URL("http://localhost"), msg);
    String authString = builder.build();
    assertNotNull(authString);
    assertTrue(authString.startsWith("OAuth"));
    System.out.println(authString);
    Map<String, String> params = unsplitAuthorization(authString.replace("OAuth ", ""));
    assertEquals(StringUtils.wrap("consumerKey", '"'), params.get("oauth_consumer_key"));
    assertEquals(StringUtils.wrap("1.0", '"'), params.get("oauth_version"));
    assertNotNull(params.get("oauth_timestamp"));
    assertNotNull(params.get("oauth_signature"));
  }

  private static Map<String, String> unsplitAuthorization(String auth) {
    return Arrays.stream(auth.split(",")).map(s -> s.split("=")).collect(Collectors.toMap(
        a -> a[0], // key
        a -> a[1] // value
        ));
  }
}
