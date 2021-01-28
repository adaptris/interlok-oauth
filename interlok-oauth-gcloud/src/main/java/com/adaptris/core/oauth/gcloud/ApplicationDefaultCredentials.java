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
import com.google.auth.oauth2.GoogleCredentials;
import com.thoughtworks.xstream.annotations.XStreamAlias;

import java.io.IOException;

/**
 * @config application-default-credentials
 */
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
