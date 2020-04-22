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


import java.io.IOException;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import com.adaptris.annotation.AutoPopulated;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.CoreException;
import com.adaptris.core.ServiceException;
import com.adaptris.core.http.oauth.AccessToken;
import com.adaptris.core.http.oauth.AccessTokenBuilder;
import com.adaptris.core.util.LifecycleHelper;
import com.google.auth.oauth2.GoogleCredentials;
import com.thoughtworks.xstream.annotations.XStreamAlias;

@XStreamAlias("google-cloud-access-token-builder")
public class GoogleCloudAccessTokenBuilder implements AccessTokenBuilder {

  @NotNull
  @Valid
  @AutoPopulated
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
      return new AccessToken(accessToken.getTokenValue()).withExpiry(accessToken.getExpirationTime());
    } catch (Exception e) {
      throw new ServiceException("Failed to retrieve credentials", e);
    }
  }

  @Override
  public void init() throws CoreException {
    LifecycleHelper.init(getCredentials());
  }

  @Override
  public void start() throws CoreException {
    LifecycleHelper.start(getCredentials());
  }

  @Override
  public void stop() {
    LifecycleHelper.stop(getCredentials());
  }

  @Override
  public void close() {
    LifecycleHelper.close(getCredentials());
  }

  public Credentials getCredentials() {
    return credentials;
  }

  public void setCredentials(Credentials credentials) {
    this.credentials = credentials;
  }
}
