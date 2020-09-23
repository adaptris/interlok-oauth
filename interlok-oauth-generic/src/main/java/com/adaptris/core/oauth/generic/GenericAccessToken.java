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

import java.util.Optional;
import java.util.stream.Collectors;
import javax.validation.Valid;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.annotation.DisplayOrder;
import com.adaptris.annotation.InputFieldDefault;
import com.adaptris.annotation.Removal;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.CoreException;
import com.adaptris.core.http.oauth.AccessTokenBuilder;
import com.adaptris.core.metadata.MetadataFilter;
import com.adaptris.core.metadata.RegexMetadataFilter;
import com.adaptris.core.util.LoggingHelper;
import com.thoughtworks.xstream.annotations.XStreamAlias;
import lombok.Getter;
import lombok.Setter;

/**
 * Wraps the a URL Form based OAuth authentication flow.
 * <p>
 * This class is designed for the situation where the OAUTH provider does not have a specific API that we can use. The sequence of
 * events is :
 * </p>
 * <ul>
 * <li>Filter the metadata to create a {@code UrlEncodedFormEntity}; the contents of the URL Form are determined solely by the
 * metadata-filter.</li>
 * <li>Post this to the configured URL.</li>
 * <li>Extract the access token information via the configured OauthResponseHandler</li>
 * <li>This then is your access token</li>
 * </p>
 * <p>
 * It is perfectly possible to achieve the same thing with standard configuration; it would be a combination of
 * {@link com.adaptris.core.services.metadata.AddMetadataService} +
 * {@link com.adaptris.core.services.metadata.CreateQueryStringFromMetadata} +
 * ({@link com.adaptris.core.http.client.net.StandardHttpProducer} || {@code ApacheHttpProducer}) + {@code JsonPathService} +
 * {@link com.adaptris.core.services.metadata.AddFormattedMetadataService}. This encapsulates all of that into a single class. If
 * you have encoded passwords in your metadata, consider using a {@link com.adaptris.core.metadata.PasswordDecodeMetadataFilter} as
 * part of a {@link com.adaptris.core.metadata.CompositeMetadataFilter}.
 * </p>
 *
 * @config generic-oauth-access-token
 * @see AccessTokenBuilder
 */
@DisplayOrder(order =
{
    "tokenUrl", "responseHandler", "metadataFilter", "clientConfig"
})
@ComponentProfile(since = "3.8.1", summary = "Get a bearer token based on a URL Form based OAuth authentication flow.", tag = "oauth,http,https")
@XStreamAlias("generic-oauth-access-token")
public class GenericAccessToken extends GenericAccessTokenImpl {

  /**
   * The metadata that will be used to build up the payload will be sent to the specified URL.
   *
   * @deprecated since 3.11.0; this member was poorly named, use 'formBuilder' instead.
   */
  @Valid
  @Getter
  @Setter
  @Deprecated
  @Removal(version="4.0", message="Poorly named use 'form-builder' instead")
  private MetadataFilter metadataFilter;

  /**
   * The form builder will be used to build up the payload will be sent to the specified URL.
   * <p>
   * By default the payload is built up from the metadata keys 'client_id', 'client_secret',
   * 'grant_type','refresh_token','username', 'password' using a {@link RegexMetadataFilter}. You
   * should change this if these are not the right keys (keys that aren't present in metadata will
   * be ignored).
   * </p>
   */
  @Valid
  @InputFieldDefault(
      value = "regex-metadata-filter with 'client_id', 'client_secret', 'grant_type','refresh_token','username', 'password'")
  @Getter
  @Setter
  private MetadataFilter formBuilder;


  private transient boolean filterWarning;

  public GenericAccessToken() {
    setFormBuilder(new RegexMetadataFilter().withIncludePatterns("client_id", "client_secret",
        "grant_type", "refresh_token", "username", "password"));
  }

  @Override
  public void init() throws CoreException {
    if (getMetadataFilter() != null) {
      LoggingHelper.logWarning(filterWarning, () -> filterWarning = true,
          "{} uses metadata-filter which is deprecated; use 'form-builder' instead",
          LoggingHelper.friendlyName(this));
    }
    super.init();
  }

  @Override
  protected HttpEntity buildEntity(AdaptrisMessage msg) throws Exception {
    return new UrlEncodedFormEntity(formBuilder().filter(msg).stream()
        .map(e -> new BasicNameValuePair(e.getKey(), e.getValue())).collect(Collectors.toList()));
  }


  // Make this use the FormBuilder setter.
  @Deprecated
  @Removal(version = "4.0.0")
  public GenericAccessToken withMetadataFilter(MetadataFilter f) {
    return withFormBuilder(f);
  }

  public GenericAccessToken withFormBuilder(MetadataFilter f) {
    setFormBuilder(f);
    return this;
  }

  private MetadataFilter formBuilder() throws CoreException {
    MetadataFilter filter = ObjectUtils.defaultIfNull(getMetadataFilter(), getFormBuilder());
    return Optional.ofNullable(filter).orElseThrow(
        () -> new CoreException(
            "No way to build OAUTH form entity; no metadata-filter or form-builder"));
  }

}
