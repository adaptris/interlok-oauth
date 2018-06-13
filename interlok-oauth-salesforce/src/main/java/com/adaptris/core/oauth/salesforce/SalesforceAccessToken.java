package com.adaptris.core.oauth.salesforce;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import org.hibernate.validator.constraints.NotBlank;

import com.adaptris.annotation.AdvancedConfig;
import com.adaptris.annotation.DisplayOrder;
import com.adaptris.annotation.InputFieldHint;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.CoreException;
import com.adaptris.core.http.client.net.StandardHttpProducer;
import com.adaptris.core.http.oauth.AccessToken;
import com.adaptris.core.http.oauth.AccessTokenBuilder;
import com.adaptris.core.http.oauth.GetOauthToken;
import com.adaptris.core.services.metadata.AddFormattedMetadataService;
import com.adaptris.core.services.metadata.AddMetadataService;
import com.adaptris.core.services.metadata.CreateQueryStringFromMetadata;
import com.adaptris.core.util.Args;
import com.adaptris.core.util.ExceptionHelper;
import com.adaptris.interlok.resolver.ExternalResolver;
import com.adaptris.security.exc.PasswordException;
import com.adaptris.security.password.Password;
import com.thoughtworks.xstream.annotations.XStreamAlias;

/**
 * Wraps the salesforce username/password OAuth authentication flow for machine/machine data flow.
 * <p>
 * Based on the java example available within the
 * <a href="https://github.com/jamesward/salesforce-rest-starter">salesforce-rest-starter</a> project and relies on the jackson json
 * jars being available on the classpath (built against {@code com.fasterxml.jackson.core:jackson-databind:2.6.2}) which has been
 * marked as optional in the dependency list to avoid additional jars if you want to just use Apache HTTP.
 * </p>
 * <p>
 * It is perfectly possible to achieve the same thing with standard configuration; it would be a combination of
 * {@link AddMetadataService} + {@link CreateQueryStringFromMetadata} + ({@link StandardHttpProducer} || {@link ApacheHttpProducer})
 * + {@code JsonPathService} + {@link AddFormattedMetadataService}. This encapsulates all of that into a single class.
 * </p>
 * 
 * @config salesforce-access-token
 * @see GetOauthToken
 * @see AccessTokenBuilder
 */
@DisplayOrder(order =
{
    "username", "password", "consumerKey", "consumerSecret", "tokenUrl", "httpProxy"
})
@XStreamAlias("salesforce-access-token")
public class SalesforceAccessToken implements AccessTokenBuilder {

  /**
   * The default URL for getting access tokens {@value #DEFAULT_TOKEN_URL}.
   * 
   */
  public static final String DEFAULT_TOKEN_URL = "https://login.salesforce.com/services/oauth2/token";

  @NotBlank
  @InputFieldHint(expression = true)
  private String username;
  @NotBlank
  @InputFieldHint(style = "password", expression = true, external = true)
  private String password;
  @NotBlank
  @InputFieldHint(expression = true)
  private String consumerKey;
  @NotBlank
  @InputFieldHint(style = "password", expression = true, external = true)
  private String consumerSecret;

  @AdvancedConfig
  private String httpProxy;
  @AdvancedConfig
  private String tokenUrl;

  public SalesforceAccessToken() {

  }

  public SalesforceAccessToken withUsernamePassword(String user, String password) {
    setUsername(user);
    setPassword(password);
    return this;
  }

  public SalesforceAccessToken withConsumerCredentials(String key, String secret) {
    setConsumerKey(key);
    setConsumerSecret(secret);
    return this;
  }

  @Override
  public void init() throws CoreException {
    try {
      Args.notBlank(getUsername(), "username");
      Args.notBlank(getPassword(), "password");
      Args.notBlank(getConsumerKey(), "consumerKey");
      Args.notBlank(getConsumerSecret(), "consumerSecret");
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
  public AccessToken build(AdaptrisMessage msg) throws IOException, CoreException {
    AccessToken token = null;
    try {
      token = createWorker().login(createEntity(msg));
    }
    catch (PasswordException | UnsupportedEncodingException e) {
      throw ExceptionHelper.wrapCoreException(e);
    }
    return token;
  }

  SalesforceLoginWorker createWorker() {
    return new SalesforceLoginWorker(tokenUrl(), getHttpProxy());
  }

  private HttpEntity createEntity(AdaptrisMessage msg) throws PasswordException, UnsupportedEncodingException {
    List<NameValuePair> login = new ArrayList<NameValuePair>();
    login.add(new BasicNameValuePair("client_id", msg.resolve(getConsumerKey())));
    login.add(new BasicNameValuePair("client_secret", Password.decode(msg.resolve(ExternalResolver.resolve(getConsumerSecret())))));
    login.add(new BasicNameValuePair("grant_type", "password"));
    login.add(new BasicNameValuePair("username", msg.resolve(getUsername())));
    login.add(new BasicNameValuePair("password", Password.decode(msg.resolve(ExternalResolver.resolve(getPassword())))));
    return new UrlEncodedFormEntity(login);
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
   * <p>
   * Remember the password is really your password + security token
   * </p>
   * 
   * @param s the password which may be encoded via {@link Password#encode(String, String)}
   */
  public void setPassword(String s) {
    this.password = Args.notBlank(s, "password");
  }

  public String getConsumerKey() {
    return consumerKey;
  }

  /**
   * Set your consumer key.
   * 
   * @param s the consumer key
   */
  public void setConsumerKey(String s) {
    this.consumerKey = Args.notBlank(s, "consumerKey");
  }

  public String getConsumerSecret() {
    return consumerSecret;
  }

  /**
   * Set your consumer secret.
   * 
   * @param s the consumer secret which may be encoded via {@link Password#encode(String, String)}
   */
  public void setConsumerSecret(String s) {
    this.consumerSecret = Args.notBlank(s, "consumerSecret");
  }

  public String getHttpProxy() {
    return httpProxy;
  }

  /**
   * Explicitly configure a proxy server.
   * 
   * @param proxy the httpProxy to generally {@code scheme://host:port} or more simply {@code host:port}
   */
  public void setHttpProxy(String proxy) {
    this.httpProxy = proxy;
  }

  public String getTokenUrl() {
    return tokenUrl;
  }

  /**
   * Set the token URL.
   * 
   * @param tokenUrl the URL, if not specified, defaults to {@value #DEFAULT_TOKEN_URL}
   */
  public void setTokenUrl(String tokenUrl) {
    this.tokenUrl = tokenUrl;
  }

  String tokenUrl() {
    return getTokenUrl() != null ? getTokenUrl() : DEFAULT_TOKEN_URL;
  }

}
