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
