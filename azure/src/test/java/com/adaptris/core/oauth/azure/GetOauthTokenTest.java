package com.adaptris.core.oauth.azure;

import com.adaptris.core.ServiceCase;
import com.adaptris.core.http.oauth.GetOauthToken;

public class GetOauthTokenTest extends ServiceCase {

  public GetOauthTokenTest(String s) {
    super(s);
  }

  @Override
  protected Object retrieveObjectForSampleConfig() {
    GetOauthToken service = new GetOauthToken();
    service.setAccessTokenBuilder(new AzureAccessToken().withUsernamePassword("myUsername", "MyPassword")
        .withClientId("MyClientId").withResource("http://resource.url/"));
    return service;
  }

}
