package com.adaptris.core.oauth.azure;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.hibernate.validator.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.adaptris.annotation.AdvancedConfig;
import com.adaptris.annotation.DisplayOrder;
import com.adaptris.annotation.InputFieldDefault;
import com.adaptris.annotation.InputFieldHint;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.CoreException;
import com.adaptris.core.http.oauth.AccessToken;
import com.adaptris.core.http.oauth.AccessTokenBuilder;
import com.adaptris.core.http.oauth.GetOauthToken;
import com.adaptris.core.util.Args;
import com.adaptris.core.util.ExceptionHelper;
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
 * @config azure-access-token
 * @see GetOauthToken
 * @see AccessTokenBuilder
 */
@DisplayOrder(order =
{
    "username", "password", "clientId", "resource", "authorityUrl", "validateAuthority"
})
@XStreamAlias("azure-access-token")
public class AzureAccessToken implements AccessTokenBuilder {

  /**
   * The default URL for getting access tokens: {@value #DEFAULT_AUTHORITY}.
   * 
   */
  public static final String DEFAULT_AUTHORITY = "https://login.microsoftonline.com/common/";
  private transient Logger log = LoggerFactory.getLogger(this.getClass());

  @NotBlank
  @InputFieldHint(expression = true)
  private String username;
  @NotBlank
  @InputFieldHint(style = "password", expression = true)
  private String password;

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
  public void init() throws CoreException {
    try {
      Args.notBlank(username, "username");
      Args.notBlank(password, "password");
      Args.notBlank(clientId, "clientId");
      Args.notBlank(resource, "resource");
    }
    catch (IllegalArgumentException e) {
      throw ExceptionHelper.wrapCoreException(e);
    }
    service = Executors.newFixedThreadPool(1);
  }

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
      AuthenticationResult azureToken = getAccessTokenFromUserCredentials(msg);
      token = new AccessToken(azureToken.getAccessTokenType(), azureToken.getAccessToken(),
          azureToken.getExpiresOnDate().getTime());
    } catch (Exception e) {
      throw ExceptionHelper.wrapCoreException(e);
    }
    return token;
  }

  private AuthenticationResult getAccessTokenFromUserCredentials(AdaptrisMessage msg) throws Exception {
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
    return getAuthorityUrl() != null ? getAuthorityUrl() : DEFAULT_AUTHORITY;
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
    return getValidateAuthority() != null ? getValidateAuthority().booleanValue() : false;
  }

  AuthenticationContext authenticationContext(AdaptrisMessage msg) throws MalformedURLException {
    return new AuthenticationContext(msg.resolve(authorityUrl()), validateAuthority(), service);
  }
}
