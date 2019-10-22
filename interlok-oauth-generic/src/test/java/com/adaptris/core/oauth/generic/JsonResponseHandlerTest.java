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

import static com.adaptris.core.oauth.generic.JsonResponseHandler.ACCESS_TOKEN_PATH;
import static com.adaptris.core.oauth.generic.JsonResponseHandler.EXPIRES_PATH;
import static com.adaptris.core.oauth.generic.JsonResponseHandler.TOKEN_TYPE_PATH;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.Test;
import com.adaptris.core.CoreException;
import com.adaptris.core.http.oauth.AccessToken;
import com.adaptris.core.util.LifecycleHelper;

public class JsonResponseHandlerTest {

  public static final String ACCESS_TOKEN_WITH_TYPE = "{\"access_token\" : \"token\", \"token_type\" : \"Bearer\"}";
  public static final String ACCESS_TOKEN_WITH_TYPE_DATE = "{\"access_token\" : \"token\", \"token_type\" : \"Bearer\", \"expires_in\" : \"2018-01-01\"}";
  public static final String ACCESS_TOKEN = "{\"access_token\" : \"token\"}";
  public static final String DUFF_JSON = "{\"blahblah\" : \"token\"}";

  @Before
  public void setUp() throws Exception {

  }

  @Test
  public void testBuildToken_WithType() throws Exception {
    JsonResponseHandler worker = new JsonResponseHandler().withExpiresPath(EXPIRES_PATH).withTokenPath(ACCESS_TOKEN_PATH)
        .withTokenTypePath(TOKEN_TYPE_PATH);
    try {
      AccessToken token = worker.buildToken(ACCESS_TOKEN_WITH_TYPE);
      assertEquals("token", token.getToken());
      assertEquals("Bearer", token.getType());
    } finally {
      LifecycleHelper.stopAndClose(worker);
    }
  }

  @Test
  public void testBuildToken_WithType_AndExpiry() throws Exception {
    JsonResponseHandler worker = new JsonResponseHandler();
    try {
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
    JsonResponseHandler worker = new JsonResponseHandler();
    try {
      AccessToken token = worker.buildToken(ACCESS_TOKEN);
      assertEquals("token", token.getToken());
      assertEquals("Bearer", token.getType());
    } finally {
      LifecycleHelper.stopAndClose(worker);
    }
  }

  @Test
  public void testBuildToken_BadJson() throws Exception {
    JsonResponseHandler worker = new JsonResponseHandler();
    try {
      AccessToken token = worker.buildToken(DUFF_JSON);
      fail();
    } catch (CoreException expected) {

    } finally {
      LifecycleHelper.stopAndClose(worker);

    }

  }

}
