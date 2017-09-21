package com.adaptris.core.oauth.gcloud;

import com.adaptris.core.CoreException;
import com.thoughtworks.xstream.annotations.XStreamImplicit;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.util.Arrays;
import java.util.List;

public abstract class ScopedCredentials implements Credentials {

  @NotNull
  @Valid
  @XStreamImplicit(itemFieldName = "scope")
  private List<String> scopes;

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
