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
import org.apache.commons.lang3.ObjectUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.annotation.DisplayOrder;
import com.adaptris.annotation.InputFieldDefault;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.CoreException;
import com.adaptris.core.http.oauth.AccessTokenBuilder;
import com.adaptris.core.metadata.MetadataFilter;
import com.adaptris.core.metadata.RegexMetadataFilter;
import com.thoughtworks.xstream.annotations.XStreamAlias;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Wraps the a URL Form based OAuth authentication flow.
 * <p>
 * This class is designed for the situation where the OAUTH provider does not have a specific API
 * that we can use. The sequence of events is :
 * </p>
 * <ul>
 * <li>Filter the metadata to create a {@code UrlEncodedFormEntity}; the contents of the URL Form
 * are determined solely by the metadata-filter.</li>
 * <li>Post this to the configured URL.</li>
 * <li>Extract the access token information via the configured OauthResponseHandler</li>
 * <li>This then is your access token</li>
 * </p>
 * <p>
 * It is perfectly possible to achieve the same thing with standard configuration; it would be a
 * combination of {@link com.adaptris.core.services.metadata.AddMetadataService} +
 * {@link com.adaptris.core.services.metadata.CreateQueryStringFromMetadata} +
 * ({@link com.adaptris.core.http.client.net.StandardHttpProducer} || {@code ApacheHttpProducer}) +
 * {@code JsonPathService} +
 * {@link com.adaptris.core.services.metadata.AddFormattedMetadataService}. This encapsulates all of
 * that into a single class. If you have encoded passwords in your metadata, consider using a
 * {@link com.adaptris.core.metadata.PasswordDecodeMetadataFilter} as part of a
 * {@link com.adaptris.core.metadata.CompositeMetadataFilter}.
 * </p>
 *
 * @config generic-oauth-access-token
 * @see AccessTokenBuilder
 */
@DisplayOrder(order =
{
    "tokenUrl", "responseHandler", "formBuilder", "clientConfig"
})
@ComponentProfile(since = "3.11.1",
    summary = "Get a bearer token based on a URL Form based OAuth authentication flow.",
    tag = "oauth,http,https")
@XStreamAlias("oauth-access-token-via-form")
@NoArgsConstructor
public class FormBasedAccessToken extends GenericAccessTokenImpl {

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


  @Override
  protected HttpEntity buildEntity(AdaptrisMessage msg) throws Exception {
    return new UrlEncodedFormEntity(formBuilder().filter(msg).stream()
        .map(e -> new BasicNameValuePair(e.getKey(), e.getValue())).collect(Collectors.toList()));
  }

  public <T extends FormBasedAccessToken> T withFormBuilder(MetadataFilter f) {
    setFormBuilder(f);
    return (T) this;
  }

  protected MetadataFilter formBuilder() throws CoreException {
    return ObjectUtils.defaultIfNull(getFormBuilder(),
        new RegexMetadataFilter().withIncludePatterns(DEFAULT_METADATA_PATTERNS));
  }

}
