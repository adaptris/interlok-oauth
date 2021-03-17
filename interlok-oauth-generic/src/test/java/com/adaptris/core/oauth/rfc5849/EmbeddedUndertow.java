package com.adaptris.core.oauth.rfc5849;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.AdaptrisMessageFactory;
import com.adaptris.core.CoreConstants;
import com.adaptris.core.http.jetty.JettyConstants;
import com.adaptris.interlok.junit.scaffolding.util.PortManager;
import com.adaptris.util.stream.StreamUtil;
import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.BlockingHandler;
import io.undertow.util.HeaderMap;
import io.undertow.util.HeaderValues;
import io.undertow.util.HttpString;

// A very very simple undertow implementation that allows us to construct AdaptrisMessage
// instances based on the message we recieve.
// We could easily bootstrap an jetty channel instead.
public class EmbeddedUndertow {

  private Integer port = null;
  private Undertow server = null;
  private ArrayDeque<ResponseMessage> httpResponses;

  private List<AdaptrisMessage> receivedMsgs;

  public EmbeddedUndertow() {
    port = PortManager.nextUnusedPort(8080);
    httpResponses = new ArrayDeque<>();
    receivedMsgs = new ArrayList<>();
  }

  public EmbeddedUndertow withResponses(ResponseMessage... s) {
    httpResponses = new ArrayDeque<>(Arrays.asList(s));
    return this;
  }

  public void start() {
    if (httpResponses.size() < 1) {
      httpResponses.add(new ResponseMessage().withBody("Hello from Undertow"));
    }
    server = Undertow.builder().addHttpListener(port, "localhost")
        .setHandler(new BlockingHandler(new MyRequestHandler()))
        .build();
    receivedMsgs = new ArrayList<>();
    server.start();
  }

  public void shutdown() {
    server.stop();
    server = null;
    PortManager.release(port);
  }

  public Integer getPort() {
    return port;
  }

  public List<AdaptrisMessage> getMessages() {
    return receivedMsgs;
  }

  private class MyRequestHandler implements HttpHandler {


    MyRequestHandler() {

    }

    @Override
    public void handleRequest(final HttpServerExchange exchange) throws Exception {
      receivedMsgs.add(createAdaptrisMessage(exchange));
      ResponseMessage wrapper = nextResponse();
      exchange.setStatusCode(wrapper.getStatus());
      for (Map.Entry<HttpString, String> e : wrapper.getHeaders().entrySet()) {
        exchange.getResponseHeaders().put(e.getKey(), e.getValue());
      }
      exchange.getResponseSender().send(wrapper.getBody());
    }

    private synchronized ResponseMessage nextResponse() {
      // We can dequeue responses from our list of responses.
      // If there's only 1 left, just re-use that.
      if (httpResponses.size() > 1) {
        return httpResponses.removeFirst();
      }
      return httpResponses.getFirst();
    }

    private AdaptrisMessage createAdaptrisMessage(HttpServerExchange exchange) throws Exception {
      AdaptrisMessage msg = AdaptrisMessageFactory.getDefaultInstance().newMessage();
      HeaderMap requestHeaders = exchange.getRequestHeaders();
      for (HeaderValues v : requestHeaders) {
        msg.addMessageHeader(v.getHeaderName().toString(), v.getFirst());
      }
      msg.addMessageHeader(CoreConstants.HTTP_METHOD, exchange.getRequestMethod().toString());
      msg.addMessageHeader(JettyConstants.JETTY_URI, exchange.getRequestURI());
      msg.addMessageHeader(JettyConstants.JETTY_URL, exchange.getRequestURL());
      StreamUtil.copyAndClose(exchange.startBlocking().getInputStream(), msg.getOutputStream());
      return msg;
    }
  }

  public class ResponseMessage {
    private String body;
    private Map<HttpString, String> headers = new HashMap<>();
    private int status = 200;

    public ResponseMessage() {

    }

    public String getBody() {
      return body;
    }

    public ResponseMessage withBody(String msg) {
      body = msg;
      return this;
    }

    public Map<HttpString, String> getHeaders() {
      return headers;
    }

    public ResponseMessage withHeaders(Map<HttpString, String> hdrs) {
      headers = hdrs;
      return this;
    }

    public int getStatus() {
      return status;
    }

    public ResponseMessage withStatus(int httpStatus) {
      status = httpStatus;
      return this;
    }
  }
}
