package com.adaptris.core.oauth.salesforce;

import com.adaptris.core.ServiceCase;
import com.adaptris.core.http.oauth.GetOauthToken;

public class GetOauthTokenTest extends ServiceCase {

  public GetOauthTokenTest(String s) {
    super(s);
  }

  @Override
  protected Object retrieveObjectForSampleConfig() {
    GetOauthToken service = new GetOauthToken();
    service.setAccessTokenBuilder(new SalesforceAccessToken().withUsernamePassword("myUsername", "MyPasswordAndAccessKey")
        .withConsumerCredentials("ConsumerKey", "ConsumerSecret"));
    return service;
  }

}
