# Checklist de seguridad · Unidad 2 — aplicada al POS

Leyenda: ✅ cumple · ❌ no cumple · 🔧 corregido en este avance · ⏭️ U3 / fuera de alcance

> Estado verificado contra el código de la rama `avance-2` (2026-11-18) y cruzado con el
> *Reporte de auditoría de seguridad (Avance U2)*. La columna **Hallazgo** usa los IDs del
> reporte; "No reportado" indica que el control falla en el código pero el reporte no tiene
> un hallazgo propio para él.
> Las rutas de **Evidencia** son relativas a `backend/src/main/java/com/curso/pv/` salvo que
> empiecen con `frontend/` o sean archivos de configuración.

## 1. Broken Access Control

| #   | Control                                                             | Estado | Hallazgo | OWASP | STRIDE | Evidencia |
|-----|---------------------------------------------------------------------|--------|----------|-------|--------|-----------|
| 1.1 | Toda ruta exige autenticación salvo las públicas explícitas         | 🔧     | BAC-01, BAC-02 | A01 | Elevation of privilege, Information disclosure, Tampering | `config/SecurityConfig.java:45-48`: solo login, logout, `/api/salud`, `/actuator/health` y `/error` son públicas. `/api/reportes/base-datos` (BAC-02) ya pide sesión. ADR-0001 |
| 1.2 | Deny by default                                                     | 🔧     | BAC-01   | A01   | Elevation of privilege | `.anyRequest().authenticated()`: toda ruta nueva nace protegida. ADR-0001 |
| 1.3 | Funciones administrativas restringidas por rol en el backend (BFLA) | ❌     | BAC-03, BAC-02 | A01 | Elevation of privilege, Tampering | No hay `hasAuthority`/`@PreAuthorize` en `avance-2`: un VENDEDOR hace `PUT`/`DELETE /api/usuarios/{id}` (`usuario/UsuarioControlador.java:17`) y lee `/api/reportes/base-datos` |
| 1.4 | El cliente no puede asignarse rol ni campos privilegiados           | ❌     | BAC-04, BAC-03 | A01 | Elevation of privilege, Spoofing | `auth/AuthServicio.java:35-58`: el registro toma `rol` del body; `usuario/UsuarioServicio.java:84`: el `PUT` acepta `"rol":"ADMIN"` |
| 1.5 | Cada acceso por id verifica la propiedad del objeto (BOLA/IDOR)     | ❌     | BAC-05   | A01   | Tampering, Information disclosure, Repudiation | `venta/VentaServicio.java:262-266, 284-296` y `venta/VentaControlador.java:92, 103`: el vendedor lee y anula la venta 2 del cajero |
| 1.6 | La identidad se toma de la sesión, no del body/URL                  | ❌     | BAC-05   | A01   | Spoofing, Repudiation | `venta/VentaServicio.java:155`: `usuarioId`/`clienteId` del checkout vienen del body; `security/UsuarioActual.java:56`, `venta/Venta.java:21` |
| 1.7 | El control del frontend no es la única barrera                      | ❌     | BAC-03   | A01   | Elevation of privilege | `frontend/src/App.jsx:21` y `frontend/src/layout/Layout.jsx:21` ocultan rutas según el rol de `localStorage`, pero el backend no repite el control de rol (1.3) |
| 1.8 | CORS restringido a orígenes conocidos                               | ❌     | BAC-06   | A05   | Spoofing, Information disclosure, Tampering | `config/CorsConfig.java:18-21`: `allowedOriginPatterns("*")` + `allowCredentials(true)` |
| 1.9 | Protección CSRF activa                                              | ❌     | BAC-06   | A05   | Tampering, Spoofing | `config/SecurityConfig.java:30`: `csrf.disable()`. `SameSite=Strict` (SES-01) lo mitiga en parte, pero no hay token |

## 2. XSS y CSP

| #   | Control                                              | Estado | Hallazgo | OWASP | STRIDE | Evidencia |
|-----|------------------------------------------------------|--------|----------|-------|--------|-----------|
| 2.1 | Sin `dangerouslySetInnerHTML` con datos del usuario  | ❌     | XSS-01, XSS-03 | A03 | Tampering, Information disclosure, Spoofing | `frontend/src/layout/Layout.jsx:64` (username); `Productos.jsx:85`, `Categorias.jsx:67`, `Clientes.jsx:119`, `FacturaDetalle.jsx:59, 78`, `Dashboard.jsx:61` |
| 2.2 | HTML generado en el servidor codificado en la salida | 🔧     | XSS-02   | A03   | Tampering, Elevation of privilege | `reporte/ReporteControlador.java`: `HtmlUtils.htmlEscape(nombreCliente)`. ADR-0002. **Parcial:** `estado`, los valores de la BD y el mensaje de error siguen sin escapar en `reporte/ReporteServicio.java:95-113` |
| 2.3 | Validación de entrada en el backend                  | ❌     | XSS-01, XSS-03 | A03 | Tampering | El registro acepta `<img src=x onerror=...>` como username y `producto/ProductoServicio.java:102` guarda HTML tal cual; no hay `@Valid` en el proyecto |
| 2.4 | `Content-Security-Policy` configurada                | ❌     | XSS-04   | A05   | Tampering, Information disclosure | `config/SecurityConfig.java:33` (`headers(h -> { })`) y `frontend/nginx.conf:8`: ninguna respuesta trae CSP |
| 2.5 | `X-Content-Type-Options`, `frame-ancestors`          | ❌     | XSS-04   | A05   | Tampering, Spoofing | La API manda los valores por defecto de Spring Security (`nosniff`, `X-Frame-Options: DENY`), pero nginx sirve el frontend sin cabeceras y no existe `frame-ancestors` |

## 3. SSRF

| #   | Control                                        | Estado | Hallazgo | OWASP | STRIDE | Evidencia |
|-----|------------------------------------------------|--------|----------|-------|--------|-----------|
| 3.1 | Lista blanca de hosts/esquemas                 | ❌     | SSRF-02, SSRF-03 | A10 | Information disclosure, Tampering, Elevation of privilege | `integracion/IntegracionServicio.java` `consultarUrl` y `enviarPost` usan la URL del usuario tal cual (p. ej. `http://localhost:8080/api/configuracion`, `http://adminer:8080/`) |
| 3.2 | Bloqueo de IPs privadas, loopback y link-local | ❌     | SSRF-01, SSRF-02, SSRF-03 | A10 | Information disclosure, Elevation of privilege | No se resuelve ni valida la IP de destino; `verificarHost` escanea `mysql:3306` y `adminer:8080` |
| 3.3 | Sin seguir redirecciones                       | 🔧     | SSRF-04  | A10   | Information disclosure | `HttpClient.Redirect.NEVER`. ADR-0006 |
| 3.4 | No se devuelve el contenido/error crudo        | ❌     | SSRF-01, SSRF-02 | A10 | Information disclosure | `IntegracionServicio`: `consultarUrl` devuelve `contenido` y `error.getMessage()`; `verificarHost` devuelve `abierto` y el error de Java. El contenido ya está limitado a 100 KB (SSRF-04) |
| 3.5 | Timeouts en el cliente HTTP                    | 🔧     | SSRF-04  | A10   | Denial of service | Connect 2 s, read 3 s, máximo 100 KB. ADR-0006 |

## 4. Exposición de datos sensibles

| #   | Control                                                      | Estado | Hallazgo | OWASP | STRIDE | Evidencia |
|-----|--------------------------------------------------------------|--------|----------|-------|--------|-----------|
| 4.1 | La API devuelve DTOs, no entidades completas                 | 🔧     | DATA-03 (pendiente DATA-01) | A01 | Information disclosure | `usuario/UsuarioDTO.java`. ADR-0004. **Parcial:** `pago/PagoControlador.java:32-36` sigue devolviendo la entidad `Pago` |
| 4.2 | Contraseñas nunca salen de la API                            | 🔧     | DATA-03  | A01, A02 | Information disclosure, Spoofing | Ni `POST /api/auth/login` ni `GET /api/usuarios` devuelven `password`, `credenciales` o `principal`. ADR-0004 |
| 4.3 | PAN enmascarado, CVV nunca devuelto                          | ❌     | DATA-01  | A01   | Information disclosure, Spoofing | `GET /api/pagos` devuelve PAN, CVV y titular; `pago/PagoServicio.java:90-91` los devuelve también al cobrar |
| 4.4 | Sin endpoints de configuración/diagnóstico públicos          | ❌     | DATA-02  | A05   | Information disclosure | Ya piden sesión (BAC-01), pero cualquier rol lee `config/ConfiguracionControlador.java:41-67` (`/api/diagnostico`: variables de entorno, password de BD, `configuracionSecreta`), `/configuracion` y `/configuracion/variables` |
| 4.5 | Actuator restringido                                         | ❌     | No reportado | A05 | Information disclosure | `application.yml`: `exposure.include: "*"`, `show-details: always`, `info.env.enabled: true`; cualquier sesión ve `env`, `heapdump`, etc. |
| 4.6 | Errores sin stack trace                                      | ❌     | DATA-04  | A05   | Information disclosure | `common/ManejadorGlobalDeErrores.java:21-23` devuelve `stackTrace`; `application.yml:4-6`: `include-stacktrace: always` |
| 4.7 | Nada sensible en localStorage / IndexedDB / cookies legibles | ❌     | No reportado (se menciona en XSS-01) | A04 | Information disclosure | `frontend/src/auth/ContextoAuth.jsx` guarda la sesión en `localStorage` (`pv_usuario`); `frontend/src/pages/Diagnostico.jsx:16` (IndexedDB) y `:60` (cookie `pv_mail` legible). La cookie `PVSESSION` ya es HttpOnly (SES-01) |

## 5. Criptografía y cifrado en reposo

| #   | Control                                        | Estado | Hallazgo | OWASP | STRIDE | Evidencia |
|-----|------------------------------------------------|--------|----------|-------|--------|-----------|
| 5.1 | Contraseñas con hash adaptativo y sal          | 🔧     | CRY-03   | A02   | Information disclosure, Spoofing | `BCryptPasswordEncoder` en `config/SecurityConfig.java` + `config/MigracionPasswordsRunner.java`. ADR-0003 |
| 5.2 | CVV nunca almacenado                           | ❌     | CRY-01, CRY-02 | A02 | Information disclosure, Spoofing | `pago/Pago.java:34` (columna `cvv`); además `pago/PagoServicio.java:83` y `log/ServicioAuditoria.java:22-41` guardan el payload con la tarjeta en `auditoria` |
| 5.3 | PAN cifrado o tokenizado                       | ❌     | CRY-01, CRY-02 | A02 | Information disclosure, Spoofing | `pago/Pago.java:30`: `numero_tarjeta` en claro; también en `auditoria.detalles` y en el log |
| 5.4 | Sin secretos en el repositorio                 | ❌     | CRY-04, DATA-02 | A02, A05 | Information disclosure, Spoofing | `database/seed.sql:102-111` (tabla `configuracion`), `application.yml` (`app.pasarela-*`, `jwt-secret`, `smtp-password`, password de BD), `pago/PagoServicio.java:23`, `docker-compose.yml` |
| 5.5 | Codificación (base64) no usada como protección | ❌     | No reportado | A02 | Information disclosure | `frontend/src/pages/Diagnostico.jsx:60`: `btoa(correo)` en una cookie legible desde JS |
| 5.6 | TLS hacia la BD y HTTPS                        | ❌     | No reportado | A02 | Information disclosure, Tampering | `useSSL=false` en `application.yml` y `docker-compose.yml`; `frontend/nginx.conf` solo escucha en el puerto 80 |

## 6. Gestión de sesiones

| #   | Control                                    | Estado | Hallazgo | OWASP | STRIDE | Evidencia |
|-----|--------------------------------------------|--------|----------|-------|--------|-----------|
| 6.1 | Cookie `HttpOnly`                          | 🔧     | SES-01   | A07   | Spoofing, Information disclosure | `application.yml`: `http-only: true`. ADR-0005, `CookieDeSesionTest` |
| 6.2 | Cookie `Secure`                            | 🔧     | SES-01   | A07   | Information disclosure | `secure: true`; fuera de `localhost` requiere HTTPS (5.6) |
| 6.3 | `SameSite` adecuado                        | 🔧     | SES-01   | A07   | Spoofing | `same-site: strict` |
| 6.4 | Expiración corta y no persistente          | 🔧     | SES-01   | A07   | Spoofing, Elevation of privilege | `timeout: 15m`, `persistent: false`, sin `max-age` |
| 6.5 | Nuevo id de sesión tras el login           | ❌     | No reportado | A07 | Spoofing | `auth/AuthControlador.java` `login` guarda el contexto sin ejecutar la estrategia de fijación, y existe `POST /api/auth/fijar-sesion` |
| 6.6 | Logout invalida la sesión                  | ❌     | SES-02   | A07   | Spoofing, Tampering, Elevation of privilege | `auth/AuthControlador.java:73-83`: solo quita el carrito; no llama a `invalidate()` y la cookie sigue siendo válida |
| 6.7 | El id de sesión no se expone en cuerpo/URL | ❌     | No reportado (se observa en DATA-03) | A07 | Information disclosure, Spoofing | `sessionId` en la respuesta de `POST /api/auth/login` y en `GET /api/auth/sesion` |
| 6.8 | Sin HTTP Basic                             | ❌     | SES-03   | A07   | Spoofing, Information disclosure | `config/SecurityConfig.java:55`: `httpBasic(basic -> { })` |

## Hallazgos del reporte sin control propio en el checklist

| Hallazgo | Estado | Relación |
|---|---|---|
| CRY-02 · Payloads sensibles en `auditoria` y logs | ❌ | Se anotó en 5.2 y 5.3. Las contraseñas ya no se auditan (DATA-03), pero los datos de tarjeta sí |
| SES-03 / SES-04 · Usuario desactivado puede iniciar sesión | ❌ | `security/UsuariosDetailsService.java:30-34` no revisa `activo`. Es un fallo de autenticación (A07) sin fila en la plantilla |

## Resumen

| Familia | 🔧 Corregido | ❌ Pendiente |
|---|---|---|
| 1. Broken Access Control | 2 | 7 |
| 2. XSS y CSP | 1 | 4 |
| 3. SSRF | 2 | 3 |
| 4. Exposición de datos sensibles | 2 | 5 |
| 5. Criptografía | 1 | 5 |
| 6. Gestión de sesiones | 4 | 4 |
| **Total** | **12** | **28** |
