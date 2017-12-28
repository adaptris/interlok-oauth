package com.adaptris.core.oauth.azure;

import java.util.ArrayList;
import java.util.List;

import com.adaptris.core.ServiceCase;
import com.adaptris.core.http.oauth.AccessTokenBuilder;
import com.adaptris.core.http.oauth.GetOauthToken;

public class GetOauthTokenTest extends ServiceCase {

  private enum AzureTokenBuilder {

    UsernamePassword() {

      @Override
      protected AccessTokenBuilder build() {
        return new AzureUsernamePasswordAccessToken().withUsernamePassword("myUsername", "MyPassword").withClientId("MyClientId")
            .withResource("http://resource.url/");
      }
      
    },
    ClientSecret() {
      @Override
      protected AccessTokenBuilder build() {
        return new AzureClientSecretAccessToken().withClientSecret("myClientSecret").withClientId("MyClientId")
            .withResource("http://resource.url/");
      }

    };

    protected abstract AccessTokenBuilder build();

  }
  public GetOauthTokenTest(String s) {
    super(s);
  }

  @Override
  protected List retrieveObjectsForSampleConfig() {
    ArrayList result = new ArrayList();
    for (AzureTokenBuilder b : AzureTokenBuilder.values()) {
      GetOauthToken service = new GetOauthToken();
      service.setAccessTokenBuilder(b.build());
      result.add(service);
    }
    return result;
  }

  @Override
  protected Object retrieveObjectForSampleConfig() {
    return null;
  }

}
