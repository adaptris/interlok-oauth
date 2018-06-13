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
