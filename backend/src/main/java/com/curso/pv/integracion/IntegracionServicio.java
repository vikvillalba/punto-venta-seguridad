package com.curso.pv.integracion;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import java.util.HashMap;
import java.util.Map;

@Service
public class IntegracionServicio {

    private static final Logger log = LoggerFactory.getLogger(IntegracionServicio.class);

    // SSRF-04: limites del cliente HTTP
    private static final int MAX_BYTES = 100_000;

    private final RestTemplate cliente = crearCliente();

    private static RestTemplate crearCliente() {
        HttpClient http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(2))
                .build();
        JdkClientHttpRequestFactory fabrica = new JdkClientHttpRequestFactory(http);
        fabrica.setReadTimeout(Duration.ofSeconds(3));
        return new RestTemplate(fabrica);
    }

    private String get(String url) {
        return cliente.execute(url, HttpMethod.GET, null, resp -> {
            try (InputStream in = resp.getBody()) {
                return new String(in.readNBytes(MAX_BYTES), StandardCharsets.UTF_8);
            }
        });
    }

    /**
     * VULNERABILIDAD (SSRF): el backend realiza la peticion a una URL que elige
     * el usuario sin ninguna validacion. Permite:
     *   - alcanzar servicios internos (localhost, red interna)
     *   - consultar metadatos de la nube en 169.254.169.254
     *   - leer archivos locales con el esquema file://
     *   - redirigir el trafico a terceros (pivote para escanear puertos)
     */
    public Map<String, Object> consultarUrl(String url) {
        Map<String, Object> respuesta = new HashMap<>();

        // VULNERABILIDAD: se registra la URL solicitada en el log
        log.info("Consultando URL externa solicitada por el cliente: {}", url);

        try {
            String cuerpo = get(url);

            respuesta.put("url", url);
            respuesta.put("estado", "OK");
            // VULNERABILIDAD: se devuelve el contenido completo de la respuesta interna
            respuesta.put("contenido", cuerpo);
            respuesta.put("longitud", cuerpo != null ? cuerpo.length() : 0);
        } catch (Exception error) {
            respuesta.put("url", url);
            respuesta.put("estado", "ERROR");
            // VULNERABILIDAD: se filtra el detalle del error, que revela la topologia interna
            respuesta.put("error", error.getMessage());
        }

        return respuesta;
    }

    /**
     * VULNERABILIDAD (SSRF con metodo POST): misma vulnerabilidad que consultarUrl,
     * pero permite enviar un cuerpo y cabeceras al servicio interno.
     */
    public Map<String, Object> enviarPost(String url, Map<String, Object> cuerpo) {
        Map<String, Object> respuesta = new HashMap<>();

        log.info("POST a URL externa solicitada por el cliente: {}", url);

        try {
            String resultado = cliente.postForObject(url, cuerpo, String.class);
            respuesta.put("url", url);
            respuesta.put("estado", "OK");
            respuesta.put("contenido", resultado);
        } catch (Exception error) {
            respuesta.put("url", url);
            respuesta.put("estado", "ERROR");
            respuesta.put("error", error.getMessage());
        }

        return respuesta;
    }

    /**
     * VULNERABILIDAD: verifica si un host responde, lo que sirve para escanear
     * puertos y descubrir servicios internos de la red del contenedor.
     */
    public Map<String, Object> verificarHost(String host, Integer puerto) {
        Map<String, Object> respuesta = new HashMap<>();
        String url = "http://" + host + ":" + puerto + "/";

        try {
            get(url);
            respuesta.put("host", host);
            respuesta.put("puerto", puerto);
            respuesta.put("abierto", true);
        } catch (Exception error) {
            respuesta.put("host", host);
            respuesta.put("puerto", puerto);
            respuesta.put("abierto", false);
            respuesta.put("error", error.getMessage());
        }

        return respuesta;
    }
}