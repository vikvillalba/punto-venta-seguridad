package com.curso.pv.config;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServer;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.boot.web.server.autoconfigure.servlet.ServletWebServerFactoryCustomizer;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Prueba del hallazgo SES-01 (cookie de sesion sin HttpOnly/Secure, 30 dias)
 * y de la decision ADR-0005.
 *
 * Reproduce la "Opcion A" del reporte (curl ... | grep -i set-cookie) sin
 * necesitar MySQL: lee el application.yml REAL del proyecto, aplica la seccion
 * server.* a un Tomcat embebido (el mismo customizer que usa Spring Boot al
 * arrancar) y monta un servlet que crea la sesion, igual que hace
 * AuthControlador.login. Luego inspecciona la cabecera Set-Cookie que Tomcat
 * envia de verdad al navegador.
 *
 * ROJO: con la configuracion original del application.yml
 *     http-only: false   -> falla "PVSESSION lleva HttpOnly"
 *     secure: false      -> falla "PVSESSION lleva Secure"
 *     same-site: lax     -> falla "PVSESSION lleva SameSite=Strict"
 *     timeout: 30d       -> falla "la sesion expira tras 15 min de inactividad"
 *                           (el contenedor reporta 2592000 s en vez de 900 s)
 *     persistent: true   -> falla "las sesiones no se persisten entre reinicios"
 * Para ver el rojo basta con restaurar esos cinco valores en
 * backend/src/main/resources/application.yml y correr:
 *     ./mvnw test -Dtest=CookieDeSesionTest
 *
 * VERDE: con http-only: true, secure: true, same-site: strict, timeout: 15m y
 * persistent: false.
 */
class CookieDeSesionTest {

    private static ServerProperties propiedades;
    private static WebServer tomcat;
    private static HttpResponse<String> respuesta;

    @BeforeAll
    static void arrancarTomcatConLaConfiguracionReal() throws Exception {
        propiedades = cargarServerPropertiesDelApplicationYml();
        propiedades.setPort(0); // puerto libre; el 8080 del yml puede estar ocupado

        TomcatServletWebServerFactory fabrica = new TomcatServletWebServerFactory();
        new ServletWebServerFactoryCustomizer(propiedades).customize(fabrica);

        tomcat = fabrica.getWebServer(contexto ->
                contexto.addServlet("login-simulado", new ServletQueCreaSesion()).addMapping("/login"));
        tomcat.start();

        respuesta = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + tomcat.getPort() + "/login"))
                        .POST(HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @AfterAll
    static void detenerTomcat() {
        if (tomcat != null) {
            tomcat.stop();
        }
    }

    @Test
    @DisplayName("Al crear la sesion se emite la cookie PVSESSION")
    void seEmiteLaCookieDeSesion() {
        assertThat(cookieDeSesion()).startsWith("PVSESSION=");
    }

    @Test
    @DisplayName("PVSESSION lleva HttpOnly (document.cookie no la ve)")
    void cookieHttpOnly() {
        // ROJO con http-only: false -> la cabecera no contiene "HttpOnly"
        assertThat(atributos()).contains("httponly");
    }

    @Test
    @DisplayName("PVSESSION lleva Secure (no viaja por HTTP sin cifrar)")
    void cookieSecure() {
        // ROJO con secure: false -> la cabecera no contiene "Secure"
        assertThat(atributos()).contains("secure");
    }

    @Test
    @DisplayName("PVSESSION lleva SameSite=Strict")
    void cookieSameSiteStrict() {
        // ROJO con same-site: lax -> la cabecera dice "SameSite=Lax"
        assertThat(atributos()).contains("samesite=strict");
    }

    @Test
    @DisplayName("PVSESSION es cookie de sesion del navegador (sin Max-Age/Expires)")
    void cookieNoPersistenteEnElNavegador() {
        // ROJO si alguien agrega server.servlet.session.cookie.max-age:
        // la cookie sobreviviria a cerrar el navegador
        assertThat(atributos()).noneMatch(a -> a.startsWith("max-age") || a.startsWith("expires"));
    }

    @Test
    @DisplayName("La sesion expira tras 15 min de inactividad")
    void timeoutCorto() {
        // ROJO con timeout: 30d -> el servlet reporta 2592000 s en vez de 900 s
        assertThat(propiedades.getServlet().getSession().getTimeout()).isEqualTo(Duration.ofMinutes(15));
        assertThat(respuesta.body()).isEqualTo("maxInactiveInterval=900");
    }

    @Test
    @DisplayName("Las sesiones no se persisten entre reinicios del servidor")
    void sesionNoPersistente() {
        // ROJO con persistent: true -> Tomcat guarda las sesiones en disco al
        // apagarse y las restaura al arrancar (una cookie robada sobrevive al reinicio)
        assertThat(propiedades.getServlet().getSession().isPersistent()).isFalse();
    }

    // ------------------------------------------------------------------ apoyo

    private static ServerProperties cargarServerPropertiesDelApplicationYml() throws IOException {
        List<PropertySource<?>> fuentes = new YamlPropertySourceLoader()
                .load("application.yml", new ClassPathResource("application.yml"));
        return new Binder(ConfigurationPropertySources.from(fuentes))
                .bindOrCreate("server", ServerProperties.class);
    }

    private static String cookieDeSesion() {
        return respuesta.headers().allValues("Set-Cookie").stream()
                .filter(c -> c.startsWith("PVSESSION="))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "No se recibio Set-Cookie PVSESSION. Cabeceras: " + respuesta.headers().map()));
    }

    /** Atributos de la cookie en minusculas y sin espacios: ["path=/", "httponly", ...]. */
    private static List<String> atributos() {
        String[] partes = cookieDeSesion().split(";");
        return java.util.Arrays.stream(partes)
                .skip(1) // la primera parte es PVSESSION=<id>
                .map(p -> p.trim().toLowerCase())
                .toList();
    }

    /** Equivalente minimo de AuthControlador.login: crea la sesion del usuario. */
    private static class ServletQueCreaSesion extends HttpServlet {
        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            int segundos = req.getSession(true).getMaxInactiveInterval();
            resp.getWriter().write("maxInactiveInterval=" + segundos);
        }
    }
}
