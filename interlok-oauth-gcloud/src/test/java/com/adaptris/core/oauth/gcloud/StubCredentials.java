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


import com.adaptris.core.CoreException;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import org.mockito.Mockito;

import java.util.Date;

import static org.mockito.Mockito.mock;

public class StubCredentials implements Credentials {

  static final String ACCESS_TOKEN = "ABC123";
  static final Date EXPIRATION = new Date(0);

  GoogleCredentials credentials;

  public StubCredentials() throws Exception{
    credentials = mock(GoogleCredentials.class);
    Mockito.when(credentials.refreshAccessToken()).thenReturn(new AccessToken(ACCESS_TOKEN, EXPIRATION));
  }

  @Override
  public GoogleCredentials build() throws CoreException {
    return credentials;
  }

  @Override
  public void init() throws CoreException {

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
}
