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

import java.net.HttpURLConnection;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import com.adaptris.annotation.AutoPopulated;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.CoreException;
import com.adaptris.core.http.HttpConstants;
import com.adaptris.core.http.auth.HttpAuthenticator;
import com.adaptris.core.http.auth.ResourceTargetMatcher;
import com.adaptris.core.http.client.net.HttpRequestService;
import com.adaptris.core.http.client.net.HttpURLConnectionAuthenticator;
import com.adaptris.core.http.client.net.StandardHttpProducer;
import com.adaptris.core.util.Args;
import com.adaptris.core.util.ExceptionHelper;
import com.thoughtworks.xstream.annotations.XStreamAlias;

/**
 * Generate an Authorization Header based on
 * <a href="https://tools.ietf.org/html/rfc5849">RFC5849</a> for use with {@link HttpRequestService}
 * and {@link StandardHttpProducer}.
 * <p>
 * NetSuite OAUTH 1.0 (using HMAC-SHA1), but not any other OAUTH 1.0 providers.
 * </p>
 * <p>
 * It is designed to generate an Authorization header based on each request that will be made,
 * rather than retrieving a {@code Bearer token} or similar for re-use. It is implemented as an
 * {@link HttpURLConnectionAuthenticator} implementation for you to add as the
 * {@link HttpRequestService#setAuthenticator(HttpAuthenticator)} or similar.
 * </p>
 * 
 * @config oauth-rfc5849-authenticator
 */
@XStreamAlias("oauth-rfc5849-authenticator")
@ComponentProfile(since = "3.8.4",
    summary = "Build an OAUTH Authorization header based on RFC5849",
    tag = "oauth,oauthv1,http.https")
public class StandardRfc5849Authenticator implements HttpURLConnectionAuthenticator {

  @NotNull
  @Valid
  @AutoPopulated
  private AuthorizationData authorizationData;

  private transient AuthorizationBuilder builder;

  public StandardRfc5849Authenticator() {
    setAuthorizationData(new AuthorizationData());
  }


  @Override
  public void setup(String target, AdaptrisMessage msg, ResourceTargetMatcher auth)
      throws CoreException {
    try {
      builder = getAuthorizationData().builder(msg);
    } catch (Exception e) {
      throw ExceptionHelper.wrapCoreException(e);
    }
  }

  @Override
  public void configureConnection(HttpURLConnection conn) throws Exception {
    conn.setRequestProperty(HttpConstants.AUTHORIZATION,
          builder.withMethod(conn.getRequestMethod()).withUrl(conn.getURL()).build());
  }

  @Override
  public void close() {
  }


  public AuthorizationData getAuthorizationData() {
    return authorizationData;
  }


  public void setAuthorizationData(AuthorizationData data) {
    authorizationData = Args.notNull(data, "authorizationData");
  }

}
