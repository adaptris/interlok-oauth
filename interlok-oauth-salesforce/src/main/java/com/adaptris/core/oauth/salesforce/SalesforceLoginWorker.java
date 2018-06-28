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

import static org.apache.commons.lang.StringUtils.isBlank;

import java.io.IOException;
import java.io.InputStream;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;

import com.adaptris.core.CoreException;
import com.adaptris.core.http.oauth.AccessToken;
import com.adaptris.core.util.ExceptionHelper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

// This is to protect against optional-packages when doing
// XStreamAlias shenanigans. We need Jackson here; but we don't want to force apache-http to
// have to always have json in the path, if we aren't using the Salesforce Access Token.
class SalesforceLoginWorker {

  private static final String TOKEN_TYPE = "token_type";
  private static final String ACCESS_TOKEN = "access_token";
  private transient String url;
  private transient String proxy;

  public SalesforceLoginWorker(String url, String proxy) {
    this.url = url;
    this.proxy = proxy;
  }

  public AccessToken login(HttpEntity entity) throws CoreException {
    try (CloseableHttpClient httpclient = createClient()) {
      HttpPost post = new HttpPost(url);
      post.setEntity(entity);
      HttpResponse loginResponse = httpclient.execute(post);
      return buildToken(loginResponse);
    }
    catch (Exception e) {
      throw ExceptionHelper.wrapCoreException(e);
    }
  }

  AccessToken buildToken(HttpResponse loginResponse) throws UnsupportedOperationException, IOException {
    try (InputStream in = loginResponse.getEntity().getContent()) {
      ObjectMapper mapper = new ObjectMapper();
      JsonNode loginResult = mapper.readValue(in, JsonNode.class);
      String accessToken = loginResult.get(ACCESS_TOKEN).asText();
      JsonNode type = loginResult.get(TOKEN_TYPE);
      if (type != null) {
        return new AccessToken(type.asText(), accessToken);
      }
      return new AccessToken(accessToken);
    }
  }

  CloseableHttpClient createClient() throws Exception {
    HttpClientBuilder builder = HttpClients.custom();
    // If someone does config a-la ${http.proxy}:${http.proxy.port} in config with var-sub
    // we end up with : as a proxy...
    if (!isBlank(proxy) && !proxy.equals(":")) {
      builder.setProxy(HttpHost.create(proxy));
    }
    return builder.build();
  }
}
