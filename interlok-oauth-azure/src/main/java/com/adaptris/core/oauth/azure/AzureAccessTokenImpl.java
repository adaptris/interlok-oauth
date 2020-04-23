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

package com.adaptris.core.oauth.azure;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.validation.constraints.NotBlank;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.adaptris.annotation.AdvancedConfig;
import com.adaptris.annotation.InputFieldDefault;
import com.adaptris.annotation.InputFieldHint;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.CoreException;
import com.adaptris.core.http.oauth.AccessToken;
import com.adaptris.core.http.oauth.AccessTokenBuilder;
import com.adaptris.core.http.oauth.GetOauthToken;
import com.adaptris.core.util.Args;
import com.adaptris.core.util.ExceptionHelper;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;

/**
 * Wraps the azure OAuth authentication flow.
 * <p>
 * Based on the example available from
 * <a href="https://github.com/Azure-Samples/active-directory-java-native-headless">Azure-Samples</a> and tested (eventually) with
 * the <a href="https://graph.microsoft.com">Microsoft Graph API</a> using
 * <a href="https://graph.microsoft.com/v1.0/me/">https://graph.microsoft.com/v1.0/me/</a>.
 * </p>
 * 
 * @config azure-access-token
 * @see GetOauthToken
 * @see AccessTokenBuilder
 */
public abstract class AzureAccessTokenImpl implements AccessTokenBuilder {

  /**
   * The default URL for getting access tokens: {@value #DEFAULT_AUTHORITY}.
   * 
   */
  public static final String DEFAULT_AUTHORITY = "https://login.microsoftonline.com/common/";
  protected transient Logger log = LoggerFactory.getLogger(this.getClass());

  @NotBlank
  @InputFieldHint(expression = true)
  private String clientId;
  @NotBlank
  @InputFieldHint(expression = true)
  private String resource;

  @AdvancedConfig
  private String authorityUrl;
  @AdvancedConfig
  @InputFieldDefault(value = "false")
  private Boolean validateAuthority;

  private transient ExecutorService service = null;

  public AzureAccessTokenImpl() {

  }

  @Override
  public final void init() throws CoreException {
    try {
      verifyConfig();
      Args.notBlank(getClientId(), "clientId");
      Args.notBlank(getResource(), "resource");
    }
    catch (IllegalArgumentException e) {
      throw ExceptionHelper.wrapCoreException(e);
    }
    service = Executors.newFixedThreadPool(1);
  }

  protected abstract void verifyConfig() throws IllegalArgumentException;

  @Override
  public void start() throws CoreException {
  }

  @Override
  public void stop() {
  }

  @Override
  public void close() {
    service.shutdown();
    service = null;
  }

  @Override
  public AccessToken build(AdaptrisMessage msg) throws IOException, CoreException {
    AccessToken token = null;
    try {
      AuthenticationResult azureToken = doAzureAuth(msg);
      token = new AccessToken(azureToken.getAccessTokenType(), azureToken.getAccessToken())
          .withExpiry(azureToken.getExpiresOnDate()).withRefreshToken(azureToken.getRefreshToken());
    } catch (Exception e) {
      throw ExceptionHelper.wrapCoreException(e);
    }
    return token;
  }


  public String getAuthorityUrl() {
    return authorityUrl;
  }

  /**
   * Set the Authority URL.
   * 
   * @param url the URL, if not specified, defaults to {@value #DEFAULT_AUTHORITY}
   */
  public void setAuthorityUrl(String url) {
    this.authorityUrl = url;
  }

  String authorityUrl() {
    return StringUtils.defaultIfEmpty(getAuthorityUrl(), DEFAULT_AUTHORITY);
  }

  public String getClientId() {
    return clientId;
  }

  /**
   * ID of the client requesting the token
   * 
   * @param s
   */
  public void setClientId(String s) {
    this.clientId = Args.notBlank(s, "clientId");
  }

  public String getResource() {
    return resource;
  }

  /**
   * Set the identifier of the target resource that is the recipient of the requested token
   */
  public void setResource(String s) {
    this.resource = Args.notBlank(s, "source");
  }

  public Boolean getValidateAuthority() {
    return validateAuthority;
  }

  /**
   * Whether or not to validate the authenticating authority.
   * 
   * @param b true to validate the authenticating authority.
   */
  public void setValidateAuthority(Boolean b) {
    this.validateAuthority = b;
  }

  boolean validateAuthority() {
    return BooleanUtils.toBooleanDefaultIfNull(getValidateAuthority(), false);
  }

  protected AuthenticationContext authenticationContext(AdaptrisMessage msg) throws MalformedURLException {
    return new AuthenticationContext(msg.resolve(authorityUrl()), validateAuthority(), service);
  }

  protected abstract AuthenticationResult doAzureAuth(AdaptrisMessage msg) throws Exception;

}
