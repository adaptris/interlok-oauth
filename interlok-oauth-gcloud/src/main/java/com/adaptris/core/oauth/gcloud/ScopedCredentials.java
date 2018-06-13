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
import com.thoughtworks.xstream.annotations.XStreamImplicit;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public abstract class ScopedCredentials implements Credentials {

  @NotNull
  @Valid
  @XStreamImplicit(itemFieldName = "scope")
  private List<String> scopes = new ArrayList<>();

  public ScopedCredentials() {
  }

  public ScopedCredentials(String... scopes){
    setScopes(Arrays.asList(scopes));
  }

  void validateArguments() throws CoreException {
    if(getScopes() == null || getScopes().size() == 0){
      throw new CoreException("Scope is invalid");
    }
  }

  @Override
  public void init() throws CoreException {
    validateArguments();
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

  public List<String> getScopes() {
    return scopes;
  }

  public void setScopes(List<String> scopes) {
    this.scopes = scopes;
  }
}
