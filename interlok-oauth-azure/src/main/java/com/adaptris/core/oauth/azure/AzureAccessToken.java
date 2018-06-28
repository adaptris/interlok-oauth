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

import com.adaptris.annotation.DisplayOrder;
import com.adaptris.core.http.oauth.AccessTokenBuilder;
import com.adaptris.core.http.oauth.GetOauthToken;
import com.thoughtworks.xstream.annotations.XStreamAlias;

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
 * @deprecated since 3.7.0 use {@link AzureUsernamePasswordAccessToken} instead for naming consistency.
 */
@DisplayOrder(order =
{
    "username", "password", "clientId", "resource", "authorityUrl", "validateAuthority"
})
@XStreamAlias("azure-access-token")
@Deprecated
public class AzureAccessToken extends AzureUsernamePasswordAccessToken {

  public AzureAccessToken() {

  }

  public AzureAccessToken withUsernamePassword(String user, String password) {
    setUsername(user);
    setPassword(password);
    return this;
  }

  public AzureAccessToken withClientId(String clientId) {
    setClientId(clientId);
    return this;
  }

  public AzureAccessToken withResource(String res) {
    setResource(res);
    return this;
  }

  @Override
  protected void verifyConfig() throws IllegalArgumentException {
    log.warn("{} is deprecated; use {} instead", getClass().getSimpleName(), AzureUsernamePasswordAccessToken.class.getName());
    super.verifyConfig();
  }
}
