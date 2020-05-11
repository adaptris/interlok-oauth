package com.adaptris.core.oauth.generic;

import java.util.Date;
import java.util.concurrent.TimeUnit;
import com.adaptris.util.text.DateFormatUtil;

/**
 * Normally the "expires_in" value if available is in Seconds but you might not want it converted or it might not be in seconds.
 * 
 */
public enum ExpiryConverter {

  NONE {
    @Override
    public long asMillis(String s) {
      return 0;
    }

    @Override
    public String convertExpiry(String s) {
      return s;
    }
  },
  MILLISECONDS {
    @Override
    public long asMillis(String s) {
      return TimeUnit.MILLISECONDS.toMillis(Long.parseLong(s));
    }
  },
  
  SECONDS {
    @Override
    public long asMillis(String s) {
      return TimeUnit.SECONDS.toMillis(Long.parseLong(s));
    }
  },
  MINUTES {
    @Override
    public long asMillis(String s) {
      return TimeUnit.MINUTES.toMillis(Long.parseLong(s));
    }
  },
  HOURS {
    @Override
    public long asMillis(String s) {
      return TimeUnit.HOURS.toMillis(Long.parseLong(s));
    }
  },
  DAYS {
    @Override
    public long asMillis(String s) {
      return TimeUnit.DAYS.toMillis(Long.parseLong(s));
    }
  };
  
  public abstract long asMillis(String s);

  public String convertExpiry(String expires_in) {
    return DateFormatUtil.format(new Date(System.currentTimeMillis() + asMillis(expires_in)));
  }
}
