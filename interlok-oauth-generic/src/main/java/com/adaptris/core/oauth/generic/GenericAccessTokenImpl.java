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

import java.io.IOException;
import java.util.function.Consumer;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolVersion;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicStatusLine;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.adaptris.annotation.AdvancedConfig;
import com.adaptris.annotation.AutoPopulated;
import com.adaptris.annotation.InputFieldDefault;
import com.adaptris.annotation.InputFieldHint;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.CoreConstants;
import com.adaptris.core.CoreException;
import com.adaptris.core.MetadataCollection;
import com.adaptris.core.http.apache.HttpClientBuilderConfigurator;
import com.adaptris.core.http.oauth.AccessToken;
import com.adaptris.core.http.oauth.AccessTokenBuilder;
import com.adaptris.core.metadata.MetadataFilter;
import com.adaptris.core.metadata.RemoveAllMetadataFilter;
import com.adaptris.core.util.Args;
import com.adaptris.core.util.ExceptionHelper;
import com.adaptris.core.util.LifecycleHelper;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

/**
 * Baseline behaviour for getting OAUTh tokens.
 *
 * @see AccessTokenBuilder
 */
public abstract class GenericAccessTokenImpl implements AccessTokenBuilder {
  protected static final StatusLine DEFAULT_STATUS =
      new BasicStatusLine(new ProtocolVersion("HTTP", 1, 1), 200, "OK");

  protected static final String[] DEFAULT_METADATA_PATTERNS =
      {"client_id", "client_secret", "grant_type", "refresh_token", "username", "password"};

  protected transient Logger log = LoggerFactory.getLogger(this.getClass());

  /**
   * The URL that will be used the retrieve the OAUTH access token.
   *
   */
  @NotBlank
  @InputFieldHint(expression = true)
  @Getter
  @Setter
  @NonNull
  private String tokenUrl;

  /**
   * How to handle the response from the server.
   * <p>
   * By default we assume a JSON based response, generally, this is the right thing
   * </p>
   */
  @NotNull
  @Valid
  @AutoPopulated
  @InputFieldDefault (value = "json based responses")
  @Getter
  @Setter
  @NonNull
  private OauthResponseHandler responseHandler;
  /**
   * Additional configuration that will be applied to the underlying Apache HTTP instance.
   *
   */
  @Valid
  @AdvancedConfig
  @Getter
  @Setter
  private HttpClientBuilderConfigurator clientConfig;

  /**
   * Specify any additional headers that you wish to send as part of the request.
   */
  @Getter
  @Setter
  @AdvancedConfig(rare = true)
  @InputFieldDefault(value = "no additional headers (remove-all-metadata-filter)")
  private MetadataFilter additionalHttpHeaders;


  private transient boolean filterWarning;

  public GenericAccessTokenImpl() {
    setResponseHandler(new JsonResponseHandler());
  }

  @Override
  public void init() throws CoreException {
    Args.notBlank(getTokenUrl(), "tokenUrl");
    Args.notNull(getResponseHandler(), "responseHandler");
    LifecycleHelper.init(getResponseHandler());
  }

  @Override
  public void start() throws CoreException {
    LifecycleHelper.start(getResponseHandler());
  }

  @Override
  public void stop() {
    LifecycleHelper.stop(getResponseHandler());
  }

  @Override
  public void close() {
    LifecycleHelper.close(getResponseHandler());
  }

  @Override
  public AccessToken build(AdaptrisMessage msg) throws CoreException {
    AccessToken token = null;
    try {
      String url = msg.resolve(getTokenUrl());
      HttpEntity entity = buildEntity(msg);
      token = login(url, entity, additionalHeaders().filter(msg),
          (code) -> msg.addMetadata(CoreConstants.HTTP_PRODUCER_RESPONSE_CODE, code.toString()));
    }
    catch (Exception e) {
      throw ExceptionHelper.wrapCoreException(e);
    }
    return token;
  }

  protected abstract HttpEntity buildEntity(AdaptrisMessage msg) throws Exception;

  protected AccessToken login(String url, HttpEntity entity, MetadataCollection httpHeaders,
      Consumer<Integer> httpStatusCallback)
      throws Exception {
    String responseBody = "";
    String httpStatusLine = "";

    try (CloseableHttpClient httpclient = HttpClientBuilderConfigurator
        .defaultIfNull(getClientConfig()).configure(HttpClients.custom()).useSystemProperties().build()) {
      HttpPost post = new HttpPost(url);
      post.setEntity(entity);
      httpHeaders.forEach((e) -> post.addHeader(e.getKey(), e.getValue()));
      CustomResponseHandler responseHandler = new CustomResponseHandler(httpStatusCallback);
      responseBody = httpclient.execute(post, responseHandler);
      httpStatusLine = responseHandler.statusLine();
      responseHandler.throwExceptionIfAny();
      return getResponseHandler().buildToken(responseBody);
    } catch (Exception e) {
      log.error("Failed to authenticate, got [{}], HTTP Reply data was : [{}]", httpStatusLine,
          responseBody);
      throw e;
    }
  }

  @SuppressWarnings("unchecked")
  public <T extends GenericAccessTokenImpl> T withTokenUrl(String url) {
    setTokenUrl(url);
    return (T) this;
  }

  @SuppressWarnings("unchecked")
  public <T extends GenericAccessTokenImpl> T withResponseHandler(OauthResponseHandler f) {
    setResponseHandler(f);
    return (T) this;
  }

  @SuppressWarnings("unchecked")
  public <T extends GenericAccessTokenImpl> T withClientConfig(HttpClientBuilderConfigurator f) {
    setClientConfig(f);
    return (T) this;
  }

  @SuppressWarnings("unchecked")
  public <T extends GenericAccessTokenImpl> T withAdditionalHeaders(MetadataFilter f) {
    setAdditionalHttpHeaders(f);
    return (T) this;
  }

  private MetadataFilter additionalHeaders() {
    return ObjectUtils.defaultIfNull(getAdditionalHttpHeaders(), new RemoveAllMetadataFilter());
  }


  protected static class CustomResponseHandler implements ResponseHandler<String> {

    private transient StatusLine statusLine = DEFAULT_STATUS;
    private transient Consumer<Integer> responseCallback;

    public CustomResponseHandler(Consumer<Integer> callback) {
      responseCallback = Args.notNull(callback, "httpResponseCallback");
    }

    @Override
    public String handleResponse(HttpResponse response) throws ClientProtocolException, IOException {
      statusLine = response.getStatusLine();
      responseCallback.accept(statusLine.getStatusCode());
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
