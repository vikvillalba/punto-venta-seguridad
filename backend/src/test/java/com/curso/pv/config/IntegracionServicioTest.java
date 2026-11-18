package com.curso.pv.config;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import com.curso.pv.integracion.IntegracionServicio;
import java.net.InetSocketAddress;
import java.util.Map;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Prueba del hallazgo SSRF-04
 */
public class IntegracionServicioTest {

    private HttpServer servidor;
    private String base;
    private final IntegracionServicio servicio = new IntegracionServicio();

    @BeforeEach
    void iniciar() throws Exception {
        servidor = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);

        servidor.createContext("/redir", ex -> {
            ex.getResponseHeaders().add("Location", "/secreto");
            ex.sendResponseHeaders(302, -1);
            ex.close();
        });
        servidor.createContext("/secreto", ex -> {
            byte[] b = "DATO-INTERNO".getBytes();
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        servidor.createContext("/lento", ex -> {
            try { Thread.sleep(10_000); } catch (InterruptedException ignorada) { }
            ex.sendResponseHeaders(200, -1);
            ex.close();
        });
        servidor.createContext("/grande", ex -> {
            byte[] b = new byte[500_000];
            java.util.Arrays.fill(b, (byte) 'a');
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });

        servidor.start();
        base = "http://127.0.0.1:" + servidor.getAddress().getPort();
    }

    @AfterEach
    void detener() {
        servidor.stop(0);
    }

    @Test
    @DisplayName("No sigue redirecciones")
    void noSigueRedirecciones() {
        Map<String, Object> r = servicio.consultarUrl(base + "/redir");
        assertThat(String.valueOf(r.get("contenido"))).doesNotContain("DATO-INTERNO");
    }

    @Test
    @DisplayName("Corta por timeout un destino lento")
    void cortaPorTimeout() {
        long inicio = System.currentTimeMillis();
        Map<String, Object> r = servicio.consultarUrl(base + "/lento");
        long ms = System.currentTimeMillis() - inicio;

        assertThat(r.get("estado")).isEqualTo("ERROR");
        assertThat(ms).isLessThan(6_000);
    }

    @Test
    @DisplayName("Limita el tamano de la respuesta")
    void limitaTamano() {
        Map<String, Object> r = servicio.consultarUrl(base + "/grande");
        assertThat(String.valueOf(r.get("contenido")).length()).isLessThanOrEqualTo(100_000);
    }
}