package com.adaptris.core.oauth.gcloud;

import com.adaptris.core.CoreException;
import com.google.auth.oauth2.GoogleCredentials;
import com.thoughtworks.xstream.annotations.XStreamAlias;

import java.io.IOException;

@XStreamAlias("application-default-credentials")
public class ApplicationDefaultCredentials extends ScopedCredentials {

  public ApplicationDefaultCredentials(){
    super();
  }

  public ApplicationDefaultCredentials(String... scopes){
    super(scopes);
  }

  @Override
  public GoogleCredentials build() throws CoreException {
    try {
      return GoogleCredentials.getApplicationDefault();
    } catch (IOException e) {
      throw new CoreException("Failed to create credential", e);
    }
  }
}
