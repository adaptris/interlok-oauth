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

  @Override
  protected String createBaseFileName(Object object) {
    GetOauthToken oauth = (GetOauthToken) object;
    return String.format("%s-%s", super.createBaseFileName(object), oauth.getAccessTokenBuilder().getClass().getSimpleName());
  }

}
