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

import com.adaptris.core.CoreException;

public abstract class ResponseHandlerImpl implements OauthResponseHandler {

  private String expiresPath;
  private String tokenTypePath;
  private String accessTokenPath;

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

  @Override
  public void init() throws CoreException {
    // override as required.
  }

  @Override
  public void start() throws CoreException {
    // override as required.
  }

  @Override
  public void stop() {
    // override as required.
  }

  @Override
  public void close() {
    // override as required.
  }
}
