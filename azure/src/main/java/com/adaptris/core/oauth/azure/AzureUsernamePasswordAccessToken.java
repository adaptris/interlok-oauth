package com.adaptris.core.oauth.azure;

import java.util.concurrent.Future;

import org.hibernate.validator.constraints.NotBlank;

import com.adaptris.annotation.DisplayOrder;
import com.adaptris.annotation.InputFieldHint;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.http.oauth.AccessTokenBuilder;
import com.adaptris.core.http.oauth.GetOauthToken;
import com.adaptris.core.util.Args;
import com.adaptris.security.password.Password;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
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
 * @config azure-username-password-access-token
 * @see GetOauthToken
 * @see AccessTokenBuilder
 */
@DisplayOrder(order =
{
    "username", "password", "clientId", "resource", "authorityUrl", "validateAuthority"
})
@XStreamAlias("azure-username-password-access-token")
public class AzureUsernamePasswordAccessToken extends AzureAccessTokenImpl {

  @NotBlank
  @InputFieldHint(expression = true)
  private String username;
  @NotBlank
  @InputFieldHint(style = "password", expression = true)
  private String password;

  public AzureUsernamePasswordAccessToken() {

  }

  public AzureUsernamePasswordAccessToken withUsernamePassword(String user, String password) {
    setUsername(user);
    setPassword(password);
    return this;
  }

  public AzureUsernamePasswordAccessToken withClientId(String clientId) {
    setClientId(clientId);
    return this;
  }

  public AzureUsernamePasswordAccessToken withResource(String res) {
    setResource(res);
    return this;
  }

  @Override
  protected void verifyConfig() throws IllegalArgumentException {
    Args.notBlank(getUsername(), "username");
    Args.notBlank(getPassword(), "password");
  }

  @Override
  protected AuthenticationResult doAzureAuth(AdaptrisMessage msg) throws Exception {
    AuthenticationContext context = authenticationContext(msg);
    Future<AuthenticationResult> future = context.acquireToken(msg.resolve(getResource()), msg.resolve(getClientId()),
        msg.resolve(getUsername()), Password.decode(msg.resolve(getPassword())), null);
    AuthenticationResult result = future.get(); // should throw an ExecutionException if it's the wrong password?
    if (result == null) {
      throw new Exception("Authentication result was null");
    }
    return result;
  }

  public String getUsername() {
    return username;
  }

  /**
   * Set the username.
   * 
   * @param s the username
   */
  public void setUsername(String s) {
    this.username = Args.notBlank(s, "username");
  }

  public String getPassword() {
    return password;
  }

  /**
   * Set the password.
   * 
   * @param s the password which may be encoded via {@link Password#encode(String, String)}
   */
  public void setPassword(String s) {
    this.password = Args.notBlank(s, "password");
  }
}
