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
import java.io.StringReader;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolVersion;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.message.BasicStatusLine;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
  private static final StatusLine DEFAULT_STATUS = new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), 200, "OK");

  private transient String url;
  private transient String proxy;

  private transient Logger log = LoggerFactory.getLogger(SalesforceAccessToken.class);

  public SalesforceLoginWorker(String url, String proxy) {
    this.url = url;
    this.proxy = proxy;
  }

  public AccessToken login(HttpEntity request) throws CoreException {
    String responseBody = "";
    String httpStatusLine = "";
    try (CloseableHttpClient httpclient = createClient()) {
      HttpPost post = new HttpPost(url);
      post.setEntity(request);
      // Since BasicResponseHandler throws an exception and doesn't give you the reply data if status >
      // 300 we need to do exactly what that does.
      CustomResponseHandler responseHandler = new CustomResponseHandler();
      responseBody = httpclient.execute(post, responseHandler);
      httpStatusLine = responseHandler.statusLine();
      responseHandler.throwExceptionIfAny();
      return buildToken(responseBody);
    }
    catch (Exception e) {
      log.error("Failed to authenticate, got [{}], HTTP Reply data was : [{}]", httpStatusLine, responseBody);
      throw ExceptionHelper.wrapCoreException(e);
    }
  }

  AccessToken buildToken(String response) throws UnsupportedOperationException, IOException {
    try (StringReader in = new StringReader(response)) {
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
    HttpClientBuilder builder = HttpClients.custom().useSystemProperties().setRedirectStrategy(LaxRedirectStrategy.INSTANCE);
    // If someone does config a-la ${http.proxy}:${http.proxy.port} in config with var-sub
    // we end up with : as a proxy...
    if (!isBlank(proxy) && !proxy.equals(":")) {
      builder.setProxy(HttpHost.create(proxy));
    }
    return builder.build();
  }

  protected static class CustomResponseHandler implements ResponseHandler<String> {

    private StatusLine statusLine = DEFAULT_STATUS;

    @Override
    public String handleResponse(HttpResponse response) throws ClientProtocolException, IOException {
      statusLine = response.getStatusLine();
      return EntityUtils.toString(response.getEntity());
    }

    protected String statusLine() {
      return statusLine.toString();
    }
    
    protected void throwExceptionIfAny() throws HttpResponseException {
      if (statusLine.getStatusCode() >= 300) {
        throw new HttpResponseException(statusLine.getStatusCode(), statusLine.getReasonPhrase());
      }
    }
  }
}
