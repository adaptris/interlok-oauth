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

import static org.apache.commons.lang3.StringUtils.isBlank;
import java.util.Optional;
import java.util.function.Consumer;
import org.apache.commons.lang3.ObjectUtils;
import com.adaptris.annotation.InputFieldDefault;

public abstract class ResponseHandlerImpl implements OauthResponseHandler {

  private String expiresPath;
  private String tokenTypePath;
  private String accessTokenPath;
  private String refreshTokenPath;

  @InputFieldDefault(value = "NONE")
  private ExpiryConverter expiryConverter;

  public String getAccessTokenPath() {
    return accessTokenPath;
  }

  /**
   * Set the path to the token.
   * 
   * @param p
   */
  public void setAccessTokenPath(String p) {
    this.accessTokenPath = p;
  }


  public <T extends ResponseHandlerImpl> T withTokenPath(String s) {
    setAccessTokenPath(s);
    return (T) this;
  }

  public String getExpiresPath() {
    return expiresPath;
  }

  /**
   * Set the path to the expires in value.
   * 
   * @param p
   */
  public void setExpiresPath(String p) {
    this.expiresPath = p;
  }

  public <T extends ResponseHandlerImpl> T withExpiresPath(String s) {
    setExpiresPath(s);
    return (T) this;
  }

  public String getTokenTypePath() {
    return tokenTypePath;
  }

  /**
   * Set the path to the token type.
   * 
   * @param p
   */
  public void setTokenTypePath(String p) {
    this.tokenTypePath = p;
  }

  public <T extends ResponseHandlerImpl> T withTokenTypePath(String s) {
    setTokenTypePath(s);
    return (T) this;
  }

  public String getRefreshTokenPath() {
    return refreshTokenPath;
  }

  /**
   * Set the path to the refresh token.
   * 
   * @param p
   */
  public void setRefreshTokenPath(String p) {
    this.refreshTokenPath = p;
  }

  public <T extends ResponseHandlerImpl> T withRefreshTokenPath(String s) {
    setRefreshTokenPath(s);
    return (T) this;
  }


  public ExpiryConverter getExpiryConverter() {
    return expiryConverter;
  }

  /**
   * Normally the "expires_in" is in SECONDS you may wish to convert it into an ISO8601 timestamp.
   * 
   * @param converter the converter; default is NONE for no conversion to preserve backwards compatible behaviours
   */
  public void setExpiryConverter(ExpiryConverter converter) {
    this.expiryConverter = converter;
  }

  public <T extends ResponseHandlerImpl> T withExpiryConverter(ExpiryConverter s) {
    setExpiryConverter(s);
    return (T) this;
  }

  protected static String convertExpiry(String expiry, ExpiryConverter converter) {
    return ObjectUtils.defaultIfNull(converter, ExpiryConverter.NONE).convertExpiry(expiry);
  }


  protected static void applyIfNotBlank(String value, Consumer<String> f) {
    Optional.ofNullable(value).filter((s) -> !isBlank(s)).ifPresent(f);
  }


  protected static void applyIfNotNull(String value, Consumer<String> f) {
    Optional.ofNullable(value).ifPresent(f);
  }
}
