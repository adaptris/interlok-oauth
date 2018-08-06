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

import java.util.stream.Collectors;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.hibernate.validator.constraints.NotBlank;

import com.adaptris.annotation.AdvancedConfig;
import com.adaptris.annotation.AutoPopulated;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.annotation.DisplayOrder;
import com.adaptris.annotation.InputFieldDefault;
import com.adaptris.annotation.InputFieldHint;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.CoreException;
import com.adaptris.core.http.apache.ApacheHttpProducer;
import com.adaptris.core.http.apache.HttpClientBuilderConfigurator;
import com.adaptris.core.http.client.net.StandardHttpProducer;
import com.adaptris.core.http.oauth.AccessToken;
import com.adaptris.core.http.oauth.AccessTokenBuilder;
import com.adaptris.core.metadata.CompositeMetadataFilter;
import com.adaptris.core.metadata.MetadataFilter;
import com.adaptris.core.metadata.NoOpMetadataFilter;
import com.adaptris.core.services.metadata.AddFormattedMetadataService;
import com.adaptris.core.services.metadata.AddMetadataService;
import com.adaptris.core.services.metadata.CreateQueryStringFromMetadata;
import com.adaptris.core.util.Args;
import com.adaptris.core.util.ExceptionHelper;
import com.thoughtworks.xstream.annotations.XStreamAlias;

/**
 * Wraps the a URL Form based OAuth authentication flow.
 * <p>
 * <ul>
 * <li>Filter the metadata to create a {@code UrlEncodedFormEntity}; the contents of the URL Form are determined solely by the
 * metadata-filter.</li>
 * <li>Post this to the configured URL.</li>
 * <li>Extract the access tken information via the configured OauthResponseHandler</li>
 * <li>This then is your access token</li>
 * </p>
 * <p>
 * It is perfectly possible to achieve the same thing with standard configuration; it would be a combination of
 * {@link AddMetadataService} + {@link CreateQueryStringFromMetadata} + ({@link StandardHttpProducer} || {@link ApacheHttpProducer})
 * + {@code JsonPathService} + {@link AddFormattedMetadataService}. This encapsulates all of that into a single class. If you have
 * encoded passwords in your metadata, consider using a {@link PasswordDecoderFilter} as part of a {@link CompositeMetadataFilter}.
 * </p>
 * 
 * @config generic-oauth-access-token
 * @see AccessTokenBuilder
 */
@DisplayOrder(order =
{
    "tokenUrl", "responseHandler", "metadataFilter", "clientConfig"
})
@ComponentProfile(since = "3.8.1")
@XStreamAlias("generic-oauth-access-token")
public class GenericAccessToken implements AccessTokenBuilder {

  @NotBlank
  @InputFieldHint(expression = true)
  private String tokenUrl;
  @NotNull
  @AutoPopulated
  @Valid
  @InputFieldDefault(value = "use all metadata")
  private MetadataFilter metadataFilter;
  @NotNull
  @Valid
  @AutoPopulated
  private OauthResponseHandler responseHandler;
  @Valid
  @AdvancedConfig
  private HttpClientBuilderConfigurator clientConfig;

  public GenericAccessToken() {
    setMetadataFilter(new NoOpMetadataFilter());
    setResponseHandler(new JsonResponseHandler());
  }

  @Override
  public void init() throws CoreException {
    try {
      Args.notBlank(getTokenUrl(), "tokenUrl");
      Args.notNull(getResponseHandler(), "responseHandler");
    } catch (IllegalArgumentException e) {
      throw ExceptionHelper.wrapCoreException(e);
    }
  }

  @Override
  public void start() throws CoreException {
  }

  @Override
  public void stop() {
  }

  @Override
  public void close() {
  }

  @Override
  public AccessToken build(AdaptrisMessage msg) throws CoreException {
    AccessToken token = null;
    try {
      String url = msg.resolve(getTokenUrl());
      HttpEntity entity = new UrlEncodedFormEntity(getMetadataFilter().filter(msg).stream()
          .map(e -> new BasicNameValuePair(e.getKey(), e.getValue())).collect(Collectors.toList()));
      token = login(url, entity);
    }
    catch (Exception e) {
      throw ExceptionHelper.wrapCoreException(e);
    }
    return token;
  }

  private AccessToken login(String url, HttpEntity entity) throws Exception {
    try (CloseableHttpClient httpclient = HttpClientBuilderConfigurator.defaultIfNull(getClientConfig())
        .configure(HttpClients.custom())
        .build()) {
      HttpPost post = new HttpPost(url);
      post.setEntity(entity);
      HttpResponse loginResponse = httpclient.execute(post);
      return getResponseHandler().buildToken(loginResponse);
    }
  }


  // private HttpEntity createEntity(AdaptrisMessage msg) throws UnsupportedEncodingException {
  // List<NameValuePair> login = new ArrayList<NameValuePair>();
  // getMetadataFilter().filter(msg).forEach(e -> {
  // login.add(new BasicNameValuePair(e.getKey(), e.getValue()));
  // });
  // return new UrlEncodedFormEntity(login);
  // }

  public String getTokenUrl() {
    return tokenUrl;
  }

  /**
   * Set the token URL.
   * 
   * @param tokenUrl the URL,
   */
  public void setTokenUrl(String tokenUrl) {
    this.tokenUrl = Args.notBlank(tokenUrl, "tokenUrl");
  }

  public GenericAccessToken withTokenUrl(String url) {
    setTokenUrl(url);
    return this;
  }

  public MetadataFilter getMetadataFilter() {
    return metadataFilter;
  }

  public void setMetadataFilter(MetadataFilter filter) {
    this.metadataFilter = Args.notNull(filter, "metadataFilter");
  }

  public GenericAccessToken withMetadataFilter(MetadataFilter f) {
    setMetadataFilter(f);
    return this;
  }

  public OauthResponseHandler getResponseHandler() {
    return responseHandler;
  }

  public void setResponseHandler(OauthResponseHandler responseHandler) {
    this.responseHandler = responseHandler;
  }

  public GenericAccessToken withResponseHandler(OauthResponseHandler f) {
    setResponseHandler(f);
    return this;
  }

  public HttpClientBuilderConfigurator getClientConfig() {
    return clientConfig;
  }

  /**
   * Specify any custom {@code HttpClientBuilder} configuration.
   * 
   * @param clientConfig a {@link HttpClientBuilderConfigurator} instance.
   */
  public void setClientConfig(HttpClientBuilderConfigurator clientConfig) {
    this.clientConfig = clientConfig;
  }

  public GenericAccessToken withClientConfig(HttpClientBuilderConfigurator f) {
    setClientConfig(f);
    return this;
  }
}
