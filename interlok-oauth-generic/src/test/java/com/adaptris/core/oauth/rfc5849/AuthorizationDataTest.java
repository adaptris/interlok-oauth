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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.URL;
import org.junit.jupiter.api.Test;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.AdaptrisMessageFactory;
import com.adaptris.core.oauth.rfc5849.AuthorizationData;
import com.adaptris.core.oauth.rfc5849.AuthorizationData.SignatureMethod;

public class AuthorizationDataTest {

  @Test
  public void testBuilderAdaptrisMessage() throws Exception {
    AuthorizationData data = new AuthorizationData();
    AdaptrisMessage msg = AdaptrisMessageFactory.getDefaultInstance().newMessage();
    try {
      data.builder(msg);
    } catch (Exception expected) {

    }
    data = configure(data);
    assertNotNull(data.builder(msg));
  }

  @Test
  public void testBuilderStringURLAdaptrisMessage() throws Exception {
    AuthorizationData data = configure(new AuthorizationData());
    AdaptrisMessage msg = AdaptrisMessageFactory.getDefaultInstance().newMessage();
    assertNotNull(data.builder("POST", new URL("http://localhost"), msg));
  }

  @Test
  public void testSetConsumerKey() {
    AuthorizationData data = new AuthorizationData();
    assertNull(data.getConsumerKey());
    data.setConsumerKey("abc");
    assertEquals("abc", data.getConsumerKey());
  }

  @Test
  public void testSetConsumerSecret() {
    AuthorizationData data = new AuthorizationData();
    assertNull(data.getConsumerSecret());
    data.setConsumerSecret("abc");
    assertEquals("abc", data.getConsumerSecret());
  }

  @Test
  public void testSetAccessToken() {
    AuthorizationData data = new AuthorizationData();
    assertNull(data.getAccessToken());
    data.setAccessToken("abc");
    assertEquals("abc", data.getAccessToken());
  }

  @Test
  public void testSetTokenSecret() {
    AuthorizationData data = new AuthorizationData();
    assertNull(data.getTokenSecret());
    data.setTokenSecret("abc");
    assertEquals("abc", data.getTokenSecret());
  }

  @Test
  public void testSetNonce() {
    AuthorizationData data = new AuthorizationData();
    assertNull(data.getNonce());
    data.setNonce("abc");
    assertEquals("abc", data.getNonce());
  }

  @Test
  public void testSetRealm() {
    AuthorizationData data = new AuthorizationData();
    assertNull(data.getRealm());
    data.setRealm("abc");
    assertEquals("abc", data.getRealm());
  }

  @Test
  public void testSetVersion() {
    AuthorizationData data = new AuthorizationData();
    assertEquals("1.0", data.version());
    data.setVersion("abc");
    assertEquals("abc", data.version());
  }

  @Test
  public void testSetIncludeEmptyParams() {
    AuthorizationData data = new AuthorizationData();
    assertFalse(data.includeEmptyParams());
    data.setIncludeEmptyParams(Boolean.TRUE);
    assertTrue(data.includeEmptyParams());
  }

  @Test
  public void testSetSignatureMethod() {
    AuthorizationData data = new AuthorizationData();
    AdaptrisMessage msg = AdaptrisMessageFactory.getDefaultInstance().newMessage();
    assertEquals(SignatureMethod.HMAC_SHA1, data.signatureMethod(msg));
    data.setSignatureMethod(SignatureMethod.HMAC_MD5.formalName());
    assertEquals(SignatureMethod.HMAC_MD5, data.signatureMethod(msg));
    data.setSignatureMethod(SignatureMethod.HMAC_MD5.name());
    assertEquals(SignatureMethod.HMAC_MD5, data.signatureMethod(msg));
  }

  @Test
  public void testSetVerifier() {
    AuthorizationData data = new AuthorizationData();
    assertNull(data.getVerifier());
    data.setVerifier("abc");
    assertEquals("abc", data.getVerifier());
  }

  protected static AuthorizationData configure(AuthorizationData d) {
    AuthorizationData result = d;
    if (result == null) {
      result = new AuthorizationData();
    }
    result.setAccessToken("accessToken");
    result.setConsumerKey("consumerKey");
    result.setConsumerSecret("consumerSecret");
    result.setTokenSecret("tokenSecret");
    return result;
  }
}
