/*
 * Copyright 2019 Adaptris Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package com.adaptris.core.oauth.rfc5849;

import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import com.adaptris.annotation.AdvancedConfig;
import com.adaptris.annotation.AffectsMetadata;
import com.adaptris.annotation.AutoPopulated;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.annotation.DisplayOrder;
import com.adaptris.annotation.InputFieldDefault;
import com.adaptris.annotation.InputFieldHint;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.CoreException;
import com.adaptris.core.MetadataCollection;
import com.adaptris.core.ServiceException;
import com.adaptris.core.ServiceImp;
import com.adaptris.core.http.HttpConstants;
import com.adaptris.core.http.apache.ApacheRequestAuthenticator;
import com.adaptris.core.metadata.MetadataFilter;
import com.adaptris.core.metadata.RemoveAllMetadataFilter;
import com.adaptris.core.util.Args;
import com.adaptris.core.util.ExceptionHelper;
import com.thoughtworks.xstream.annotations.XStreamAlias;

/**
 * Generate an RFC5849 Authorization Header based on
 * <a href="https://tools.ietf.org/html/rfc5849">RFC5849</a> and store the result as metadata.
 * <p>
 * Normally, you would use {@link ApacheRfc5849Authenticator} as your
 * {@link ApacheRequestAuthenticator} but since generation of the header does not rely on external
 * connectivity, we can generate the header offline and store it as metadata.
 * </p>
 * <p>
 * If the payload is going to be {@code application/x-www-url-form-encoded} then the request body
 * also needs to be included in the signature base string. You would specify a filter that gives you
 * the parameters; and subsequently use a
 * {@link com.adaptris.core.services.metadata.FormDataFromMetadata} to generate the payload.
 * </p>
 *
 * @config oauth-rfc5849-header-service
 * @see com.adaptris.core.services.metadata.FormDataFromMetadata
 */
@XStreamAlias("oauth-rfc5849-header-service")
@ComponentProfile(
    since = "3.8.4",
    summary = "Build an RFC5849 OAUTH Authorization header and store it as metadata",
    tag = "oauth,oauthv1,http,https")
@DisplayOrder(
    order = {"httpMethod", "url", "authorizationData", "targetMetadataKey"})
public class GenerateRfc5849Header extends ServiceImp {

  @InputFieldHint(expression = true)
  @NotBlank
  private String url;
  @InputFieldDefault(value = "POST")
  @InputFieldHint(expression = true)
  @NotBlank
  @AutoPopulated
  private String httpMethod;
  @InputFieldDefault(value = HttpConstants.AUTHORIZATION)
  @AdvancedConfig
  @AffectsMetadata
  private String targetMetadataKey;
  @NotNull
  @Valid
  @AutoPopulated
  private AuthorizationData authorizationData;
  @AdvancedConfig
  @InputFieldDefault(value = "no additional data")
  private MetadataFilter additionalData;

  public GenerateRfc5849Header() {
    setHttpMethod("POST");
    setAuthorizationData(new AuthorizationData());
  }

  @Override
  public void doService(AdaptrisMessage msg) throws ServiceException {
    try {     
      Map<String, String> additional = urlEncodeValues(additionalDataFilter().filter(msg));
      AuthorizationBuilder builder =
          getAuthorizationData()
              .builder(msg.resolve(getHttpMethod()), new URL(msg.resolve(getUrl())), msg)
              .withAdditionalData(additional);
      msg.addMessageHeader(targetMetadataKey(), builder.build());
    } catch (Exception e) {
      throw ExceptionHelper.wrapServiceException(e);
    }
  }

  @Override
  public void prepare() throws CoreException {

  }

  @Override
  protected void initService() throws CoreException {
    try {
      Args.notBlank(getUrl(), "url");
      Args.notNull(getAuthorizationData(), "authorizationData");
      Args.notBlank(getHttpMethod(), "httpMethod");
    } catch (IllegalArgumentException e) {
      throw ExceptionHelper.wrapCoreException(e);
    }
  }

  @Override
  protected void closeService() {
  }

  public String getHttpMethod() {
    return httpMethod;
  }

  /**
   * Set the HTTP method.
   *
   */
  public void setHttpMethod(String s) {
    httpMethod = Args.notBlank(s, "httpMethod");
  }

  public String getUrl() {
    return url;
  }

  /**
   * Set the URL that you will be sending to.
   *
   * @param url the URL, including any query parameters
   */
  public void setUrl(String url) {
    this.url = Args.notBlank(url, "url");
  }

  public String getTargetMetadataKey() {
    return targetMetadataKey;
  }

  /**
   * Set the metadata key where the authorization header will be stored.
   * 
   * @param s the metadata key, default is {@code Authorization} if not specified.
   */
  public void setTargetMetadataKey(String s) {
    targetMetadataKey = Args.notBlank(s, "targetMetadataKey");
  }

  private String targetMetadataKey() {
    return StringUtils.defaultIfEmpty(getTargetMetadataKey(), HttpConstants.AUTHORIZATION);
  }

  public AuthorizationData getAuthorizationData() {
    return authorizationData;
  }

  /**
   * Specify the settings that will be used to build the header.
   * 
   * @param data the {@link AuthorizationData}
   */
  public void setAuthorizationData(AuthorizationData data) {
    authorizationData = Args.notNull(data, "authorizationData");
  }

  public MetadataFilter getAdditionalData() {
    return additionalData;
  }

  /**
   * Set any additional data that needs to be used for the base signature string.
   * <p>
   * If the payload is going to be {@code application/x-www-url-form-encoded} then the request body
   * also needs to be included in the signature base string. You would specify a filter that gives
   * you the parameters; and subsequently use a
   * {@link com.adaptris.core.services.metadata.FormDataFromMetadata} to generate the payload.
   * </p>
   * 
   * @param filter a filter on metadata.
   */
  public void setAdditionalData(MetadataFilter filter) {
    this.additionalData = filter;
  }

  private MetadataFilter additionalDataFilter() {
    return ObjectUtils.defaultIfNull(getAdditionalData(), new RemoveAllMetadataFilter());
  }

  private static Map<String, String> urlEncodeValues(MetadataCollection collection)
      throws UnsupportedEncodingException {
    Map<String, String> map = MetadataCollection.asMap(collection);
    for (Map.Entry<String, String> entry : map.entrySet() ) {
      entry.setValue(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8.name()));
    }
    return map;
  }

  public GenerateRfc5849Header withAuthorizationData(AuthorizationData data) {
    setAuthorizationData(data);
    return this;
  }

  public GenerateRfc5849Header withTargetMetadataKey(String s) {
    setTargetMetadataKey(s);
    return this;
  }

  public GenerateRfc5849Header withAdditionalData(MetadataFilter filter) {
    setAdditionalData(filter);
    return this;
  }

  public GenerateRfc5849Header withUrl(String s) {
    setUrl(s);
    return this;
  }

  public GenerateRfc5849Header withMethod(String s) {
    setHttpMethod(s);
    return this;
  }
}
