package hbp.mip.utils;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/** Exaflow requires this header when its EXAFLOW_API_TOKEN is set. */
class HTTPUtilApiTokenTest {

    private final AtomicReference<String> authorization = new AtomicReference<>();
    private HttpServer server;
    private String url;

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        server.start();
        url = "http://127.0.0.1:" + server.getAddress().getPort() + "/analysis";
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    @Test
    void getAndPostSendTheTokenWhenSet() throws IOException {
        HTTPUtil.sendGet(url, "secret", new StringBuilder());
        assertThat(authorization.get()).isEqualTo("Bearer secret");

        authorization.set(null);
        HTTPUtil.sendPost(url, "secret", "{}", new StringBuilder());
        assertThat(authorization.get()).isEqualTo("Bearer secret");
    }

    @Test
    void noTokenSendsNoHeader() throws IOException {
        HTTPUtil.sendGet(url, "", new StringBuilder());
        assertThat(authorization.get()).isNull();
    }
}
