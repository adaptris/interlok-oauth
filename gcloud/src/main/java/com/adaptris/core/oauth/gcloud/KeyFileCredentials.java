package com.adaptris.core.oauth.gcloud;


import com.adaptris.core.CoreException;
import com.adaptris.core.fs.FsHelper;
import com.google.auth.oauth2.GoogleCredentials;
import com.thoughtworks.xstream.annotations.XStreamAlias;
import org.apache.commons.lang.StringUtils;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.io.File;
import java.io.FileInputStream;
import java.net.URL;

@XStreamAlias("key-file-credentials")
public class KeyFileCredentials extends ScopedCredentials {

  @NotNull
  @Valid
  private String jsonKeyFile;

  public KeyFileCredentials(){
    super();
  }

  public KeyFileCredentials(String... scopes){
    super(scopes);
  }

  @Override
  void validateArguments() throws CoreException {
    if (StringUtils.isEmpty(getJsonKeyFile())){
      throw new CoreException("Json Key File is invalid");
    }
    super.validateArguments();
  }

  @Override
  public GoogleCredentials build() throws CoreException {
    try {
      URL url = FsHelper.createUrlFromString(getJsonKeyFile(), true);
      File jsonKey = FsHelper.createFileReference(url);
      return GoogleCredentials.fromStream(new FileInputStream(jsonKey)).createScoped(getScopes());
    } catch (Exception e) {
      throw new CoreException(e);
    }
  }

  public String getJsonKeyFile() {
    return jsonKeyFile;
  }

  public void setJsonKeyFile(String jsonKeyFile) {
    this.jsonKeyFile = jsonKeyFile;
  }
}
