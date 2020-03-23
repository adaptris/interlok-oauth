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

import java.util.EnumSet;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.annotation.DisplayOrder;
import com.adaptris.core.CoreException;
import com.adaptris.core.http.oauth.AccessToken;
import com.adaptris.core.util.ExceptionHelper;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.jayway.jsonpath.PathNotFoundException;
import com.jayway.jsonpath.ReadContext;
import com.jayway.jsonpath.spi.json.JsonSmartJsonProvider;
import com.jayway.jsonpath.spi.mapper.JacksonMappingProvider;
import com.thoughtworks.xstream.annotations.XStreamAlias;

/**
 * Handle an OAUTH JSON response.
 * 
 * <p>
 * Configure the various token values using standard {@code jsonpath} notation; they will be extracted from the HTTP response to
 * build the access token.
 * </p>
 * 
 * @config oauth-json-response
 */
@XStreamAlias("oauth-json-response")
@ComponentProfile(since = "3.8.1", summary = "Handle an OAUTH JSON response.", tag = "oauth,http,https")
@DisplayOrder(order = {"accessTokenPath", "tokenTypePath", "expiresPath", "refreshTokenPath", "expiryConverter"})
public class JsonResponseHandler extends ResponseHandlerImpl {
  /**
   * Default JSON Path to the TokenType - {@value #TOKEN_TYPE_PATH}
   * 
   */
  public static final String TOKEN_TYPE_PATH = "$.token_type";
  /**
   * Default JSON Path to the Access Token - {@value #ACCESS_TOKEN_PATH}
   * 
   */
  public static final String ACCESS_TOKEN_PATH = "$.access_token";
  /**
   * Default JSON Path to the Expires value - {@value #EXPIRES_PATH}
   * 
   */
  public static final String EXPIRES_PATH = "$.expires_in";

  /**
   * Default JSON path to the refresh token {@value #REFRESH_TOKEN_PATH}.
   */
  public static final String REFRESH_TOKEN_PATH = "$.refresh_token";

  private transient Configuration jsonConfig;

  public JsonResponseHandler() {
    super();
    setAccessTokenPath(ACCESS_TOKEN_PATH);
    setExpiresPath(EXPIRES_PATH);
    setTokenTypePath(TOKEN_TYPE_PATH);
    setRefreshTokenPath(REFRESH_TOKEN_PATH);
    jsonConfig = new Configuration.ConfigurationBuilder().jsonProvider(new JsonSmartJsonProvider())
        .mappingProvider(new JacksonMappingProvider()).options(EnumSet.noneOf(Option.class)).build();
  }

  @Override
  public AccessToken buildToken(String loginResponse) throws CoreException {
    try {
      ReadContext ctx = JsonPath.parse(loginResponse, jsonConfig);
      // Will throw a PathNotFound, which is probably correct, if we can't find a token, it's all bad.
      String accessToken = ctx.read(getAccessTokenPath()).toString();
      AccessToken token = new AccessToken(accessToken);     
      String tokenType = findQuietly(ctx, getTokenTypePath());
      if (tokenType != null) {
        token.setType(tokenType);
      }
      String expiry = findQuietly(ctx, getExpiresPath());
      if (expiry != null) {
        token.setExpiry(convertExpiry(expiry, getExpiryConverter()));
      }
      String refreshToken = findQuietly(ctx, getRefreshTokenPath());
      if (refreshToken != null) {
        token.setRefreshToken(refreshToken);
      }
      return token;
    } catch (Exception e) {
      throw ExceptionHelper.wrapCoreException(e);
    }
  }

  private String findQuietly(ReadContext ctx, String path) {
    String result = null;
    try {
      result = ctx.read(path).toString();
    } catch (PathNotFoundException e) {
    }
    return result;
  }
}
