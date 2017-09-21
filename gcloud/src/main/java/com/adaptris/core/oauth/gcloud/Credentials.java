package com.adaptris.core.oauth.gcloud;


import com.adaptris.core.ComponentLifecycle;
import com.adaptris.core.CoreException;
import com.google.auth.oauth2.GoogleCredentials;

public interface Credentials extends ComponentLifecycle {

  GoogleCredentials build() throws CoreException;
}
