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

import static com.adaptris.core.oauth.generic.XmlResponseHandler.ACCESS_TOKEN_PATH;
import static com.adaptris.core.oauth.generic.XmlResponseHandler.EXPIRES_PATH;
import static com.adaptris.core.oauth.generic.XmlResponseHandler.TOKEN_TYPE_PATH;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import org.junit.Before;
import org.junit.Test;
import com.adaptris.core.CoreException;
import com.adaptris.core.http.oauth.AccessToken;
import com.adaptris.core.util.DocumentBuilderFactoryBuilder;
import com.adaptris.core.util.LifecycleHelper;
import com.adaptris.util.KeyValuePairSet;
import com.adaptris.util.text.DateFormatUtil;

public class XmlResponseHandlerTest {

  public static final String ACCESS_TOKEN_WITH_TYPE = "<root><access_token>token</access_token><token_type>Bearer</token_type></root>";
  public static final String ACCESS_TOKEN_WITH_TYPE_DATE = "<root><access_token>token</access_token><token_type>Bearer</token_type><expires_in>2018-01-01</expires_in></root>";

  public static final String ACCESS_TOKEN = "<root><access_token>token</access_token></root>";
  public static final String DUFF_XML = "<root></root>";
  public static final String ACCESS_TOKEN_WITH_REFRESH =
      "<root><access_token>token</access_token><token_type>Bearer</token_type><expires_in>600</expires_in><refresh_token>TheRefreshToken</refresh_token></root>";

  @Before
  public void setUp() throws Exception {

  }

  @Test
  public void testBuildToken_WithType() throws Exception {
    XmlResponseHandler worker = new XmlResponseHandler().withExpiresPath(EXPIRES_PATH).withTokenPath(ACCESS_TOKEN_PATH)
        .withTokenTypePath(TOKEN_TYPE_PATH);
    try {
      LifecycleHelper.initAndStart(worker);
      AccessToken token = worker.buildToken(ACCESS_TOKEN_WITH_TYPE);

      assertEquals("token", token.getToken());
      assertEquals("Bearer", token.getType());
    } finally {
      LifecycleHelper.stopAndClose(worker);
    }

  }

  @Test
  public void testBuildToken_WithType_AndExpiry() throws Exception {
    XmlResponseHandler worker = new XmlResponseHandler().withXmlDocumentFactoryConfig(null).withNamespaceContext(null);
    try {
      LifecycleHelper.initAndStart(worker);
      AccessToken token = worker.buildToken(ACCESS_TOKEN_WITH_TYPE_DATE);
      assertEquals("token", token.getToken());
      assertEquals("Bearer", token.getType());
      assertEquals("2018-01-01", token.getExpiry());
    } finally {
      LifecycleHelper.stopAndClose(worker);
    }

  }

  @Test
  public void testBuildToken_NoType() throws Exception {
    XmlResponseHandler worker = new XmlResponseHandler().withNamespaceContext(new KeyValuePairSet())
        .withXmlDocumentFactoryConfig(DocumentBuilderFactoryBuilder.newInstance());
    try {
      LifecycleHelper.initAndStart(worker);
      AccessToken token = worker.buildToken(ACCESS_TOKEN);
      assertEquals("token", token.getToken());
      assertEquals("Bearer", token.getType());
    } finally {
      LifecycleHelper.stopAndClose(worker);
    }

  }

  @Test
  public void testBuildToken_BadXml() throws Exception {
    XmlResponseHandler worker = new XmlResponseHandler();
    try {
      LifecycleHelper.initAndStart(worker);
      AccessToken token = worker.buildToken(DUFF_XML);
      fail();
    } catch (CoreException expected) {
    } finally {
      LifecycleHelper.stopAndClose(worker);
    }

  }

  @Test
  public void testBuildToken_WithRefreshToken() throws Exception {
    XmlResponseHandler worker = new XmlResponseHandler().withXmlDocumentFactoryConfig(null).withNamespaceContext(null)
        .withExpiryConverter(ExpiryConverter.SECONDS);
    try {
      LifecycleHelper.initAndStart(worker);
      AccessToken token = worker.buildToken(ACCESS_TOKEN_WITH_REFRESH);
      assertEquals("token", token.getToken());
      assertEquals("Bearer", token.getType());
      assertEquals("TheRefreshToken", token.getRefreshToken());
      // now + 10 minutes = sometime after now + 9 minutes ;)
      Date expires = DateFormatUtil.parse(token.getExpiry());
      Date expected = new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(9L));
      assertTrue(expires.after(expected));
    } finally {
      LifecycleHelper.stopAndClose(worker);
    }

  }
}
