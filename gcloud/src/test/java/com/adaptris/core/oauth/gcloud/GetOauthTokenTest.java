package com.adaptris.core.oauth.gcloud;

import com.adaptris.core.ServiceCase;
import com.adaptris.core.http.oauth.GetOauthToken;

import java.util.Arrays;

public class GetOauthTokenTest extends ServiceCase {

  public GetOauthTokenTest(String s) {
    super(s);
  }

  @Override
  protected Object retrieveObjectForSampleConfig() {
    GetOauthToken service = new GetOauthToken();
    ApplicationDefaultCredentials applicationDefaultCredentials = new ApplicationDefaultCredentials();
    applicationDefaultCredentials.setScopes(Arrays.asList("https://www.googleapis.com/auth/pubsub"));
    GoogleCloudAccessTokenBuilder tokenBuilder = new GoogleCloudAccessTokenBuilder(applicationDefaultCredentials);
    service.setAccessTokenBuilder(tokenBuilder);
    return service;
  }

}
