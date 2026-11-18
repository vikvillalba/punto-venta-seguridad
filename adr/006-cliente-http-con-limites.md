# ADR-0006 · Cliente HTTP con timeouts, sin redirecciones y con límite de tamaño

- **Estado:** Aceptado
- **Fecha:** 2026-11-18
- **Autor(es):** Marisol Ruiz Pacheco
- **Hallazgos relacionados:** SSRF-04

## Contexto

`IntegracionServicio` crea su cliente HTTP sin ninguna configuración
(`IntegracionServicio.java:16`):

```java
private final RestTemplate cliente = new RestTemplate();
```

Ese cliente lo usan `consultarUrl`, `enviarPost` y `verificarHost`. Se verificó
por revisión de código que no hay timeouts, límite de tamaño ni control de
redirecciones. Esto tiene tres consecuencias:

- **Sin timeouts:** una petición a un destino lento deja un hilo del servidor
  esperando sin límite. Varias a la vez pueden degradar el POS en horas de venta
  (Denial of service).
- **Sin límite de tamaño:** `consultarUrl` carga completa en memoria la respuesta
  del destino.
- **Redirecciones seguidas por defecto:** una validación que solo revise la URL
  inicial se puede saltar con una redirección hacia un destino interno
  (Information disclosure).

OWASP A10 — Server-Side Request Forgery.

## Decisión

Se crea el cliente con un `HttpClient` de Java configurado y se lee la respuesta
con un tope de bytes:

```java
private static final int MAX_BYTES = 100_000;

private static RestTemplate crearCliente() {
    HttpClient http = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(2))
            .build();
    JdkClientHttpRequestFactory fabrica = new JdkClientHttpRequestFactory(http);
    fabrica.setReadTimeout(Duration.ofSeconds(3));
    return new RestTemplate(fabrica);
}
```

| Control | Valor | Por qué |
|---|---|---|
| Connect timeout | 2 s | Un destino que no responde no retiene el hilo |
| Read timeout | 3 s | Un destino que responde lento se corta |
| Redirecciones | Desactivadas | Evita saltarse una validación inicial con un 302 |
| Tamaño máximo | 100 KB | La respuesta nunca se carga completa en memoria |

`consultarUrl` y `verificarHost` usan un método `get(url)` que lee como máximo
`MAX_BYTES`. `enviarPost` hereda los timeouts y la regla de no seguir
redirecciones al usar el mismo cliente.

## Alternativas consideradas

| Opción | Pros | Contras |
|---|---|---|
| Dejarlo como está | Sin cambios | Un destino lento o grande degrada el servidor; las redirecciones permiten saltarse validaciones |
| `SimpleClientHttpRequestFactory` | Más sencillo | Para no seguir redirecciones hay que sobrescribir `prepareConnection`; el cliente del JDK lo ofrece por configuración |
| Cambiar a `WebClient` o Apache HttpClient | Más control | Dependencia nueva y refactor de todo el servicio para un cambio puntual |
| **`JdkClientHttpRequestFactory` con `HttpClient` configurado (elegida)** | Sin dependencias nuevas, configuración declarativa, cambio mínimo | Hay que acordarse de no crear otro `RestTemplate` sin configurar |

## Consecuencias

- **Positivas:**
  - Una petición a un destino lento termina en pocos segundos y libera el hilo.
  - Una respuesta enorme ya no se carga completa en memoria.
  - Una redirección ya no lleva a destinos que la validación inicial no revisó.
- **Negativas / costos:**
  - **Esta corrección no impide el SSRF.** El servidor sigue aceptando cualquier
    host y puerto, así que SSRF-01, SSRF-02 y SSRF-03 siguen abiertos. Hace falta una
    lista blanca de hosts y bloquear rangos privados, y se corrige por separado.
  - Una URL legítima que responda con redirección ya no se sigue.
  - Las respuestas mayores a 100 KB se devuelven truncadas.
- **Prueba que demuestra el control:** `backend/src/test/java/com/curso/pv/config/IntegracionServicioTest.java`
  - Levanta un servidor local con tres destinos: uno que redirige hacia un
    recurso con un dato interno, uno que tarda 10 s y uno que responde 500 KB.
  - Comprueba que la redirección no se sigue, que la petición lenta termina con
    `estado=ERROR` en menos de 6 s y que el contenido no pasa de 100 KB.

  Resultado:

  | Versión de `IntegracionServicio` | Resultado |
  |---|---|
  | Original (`new RestTemplate()`) | 🔴 `Tests run: 3, Failures: 3` |
  | Con el fix | 🟢 `Tests run: 3, Failures: 0` |

  Comando: `cd backend && ./mvnw test -Dtest=IntegracionServicioTest`