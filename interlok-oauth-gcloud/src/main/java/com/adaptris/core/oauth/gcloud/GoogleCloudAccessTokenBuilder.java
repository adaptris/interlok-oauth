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

package com.adaptris.core.oauth.gcloud;


import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.CoreException;
import com.adaptris.core.ServiceException;
import com.adaptris.core.http.oauth.AccessToken;
import com.adaptris.core.http.oauth.AccessTokenBuilder;
import com.google.auth.oauth2.GoogleCredentials;
import com.thoughtworks.xstream.annotations.XStreamAlias;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.io.IOException;

@XStreamAlias("google-cloud-access-token-builder")
public class GoogleCloudAccessTokenBuilder implements AccessTokenBuilder {

  @NotNull
  @Valid
  private Credentials credentials;

  public GoogleCloudAccessTokenBuilder(){
    setCredentials(new ApplicationDefaultCredentials());
  }

  public GoogleCloudAccessTokenBuilder(Credentials credentials){
    setCredentials(credentials);
  }

  @Override
  public AccessToken build(AdaptrisMessage adaptrisMessage) throws IOException, CoreException {
    try {
      GoogleCredentials credential = getCredentials().build();
      com.google.auth.oauth2.AccessToken accessToken = credential.refreshAccessToken();
      return new AccessToken(accessToken.getTokenValue(), accessToken.getExpirationTime().getTime());
    } catch (Exception e) {
      throw new ServiceException("Failed to retrieve credentials", e);
    }
  }

  @Override
  public void init() throws CoreException {
    getCredentials().init();
  }

  @Override
  public void start() throws CoreException {
    getCredentials().start();
  }

  @Override
  public void stop() {
    getCredentials().stop();
  }

  @Override
  public void close() {
    getCredentials().close();
  }

  public Credentials getCredentials() {
    return credentials;
  }

  public void setCredentials(Credentials credentials) {
    this.credentials = credentials;
  }
}
