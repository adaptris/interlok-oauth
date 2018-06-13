package com.adaptris.core.oauth.azure;

import java.util.concurrent.Future;

import org.hibernate.validator.constraints.NotBlank;

import com.adaptris.annotation.DisplayOrder;
import com.adaptris.annotation.InputFieldHint;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.http.oauth.AccessTokenBuilder;
import com.adaptris.core.http.oauth.GetOauthToken;
import com.adaptris.core.util.Args;
import com.adaptris.interlok.resolver.ExternalResolver;
import com.adaptris.security.password.Password;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
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
 * @config azure-client-secret-access-token
 * @see GetOauthToken
 * @see AccessTokenBuilder
 */
@DisplayOrder(order =
{
    "clientId", "clientSecret", "resource", "authorityUrl", "validateAuthority"
})
@XStreamAlias("azure-client-secret-access-token")
public class AzureClientSecretAccessToken extends AzureAccessTokenImpl {

  @NotBlank
  @InputFieldHint(expression = true, style = "PASSWORD", external = true)
  private String clientSecret;

  public AzureClientSecretAccessToken() {

  }

  public AzureClientSecretAccessToken withClientId(String clientId) {
    setClientId(clientId);
    return this;
  }

  public AzureClientSecretAccessToken withClientSecret(String secret) {
    setClientSecret(secret);
    return this;
  }

  public AzureClientSecretAccessToken withResource(String res) {
    setResource(res);
    return this;
  }

  @Override
  protected void verifyConfig() throws IllegalArgumentException {
    Args.notBlank(getClientSecret(), "clientSecret");
  }

  @Override
  protected AuthenticationResult doAzureAuth(AdaptrisMessage msg) throws Exception {
    AuthenticationContext context = authenticationContext(msg);
    ClientCredential secret = new ClientCredential(msg.resolve(getClientId()),
        Password.decode(msg.resolve(ExternalResolver.resolve(getClientSecret()))));
    Future<AuthenticationResult> future = context.acquireToken(msg.resolve(getResource()), secret, null);
    AuthenticationResult result = future.get();
    if (result == null) {
      throw new Exception("Authentication result was null");
    }
    return result;
  }


  public String getClientSecret() {
    return clientSecret;
  }

  /**
   * Set the client secret when accessing a token.
   * 
   * @param s the client secret which may be encoded via {@link Password#encode(String, String)}
   */
  public void setClientSecret(String s) {
    this.clientSecret = Args.notBlank(s, "clientSecret");
  }

}
