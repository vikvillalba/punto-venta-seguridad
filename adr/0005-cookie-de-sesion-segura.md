# ADR-0005 · Cookie de sesión HttpOnly, Secure, SameSite=Strict y de vida corta

- **Estado:** Aceptado
- **Fecha:** 2026-11-17
- **Autor(es):** Victoria Isabel Villalba Beltrán
- **Hallazgos relacionados:** SES-01

## Contexto

La cookie de sesión `PVSESSION` se configuraba explícitamente sin protección en
`backend/src/main/resources/application.yml`:

```yaml
servlet:
  session:
    cookie:
      name: PVSESSION
      http-only: false
      secure: false
      same-site: lax
    timeout: 30d
    persistent: true
```

Se verificó con `curl -i -X POST http://localhost:8080/api/auth/login ... | grep -i set-cookie`:
la cabecera que envía Tomcat es `Set-Cookie: PVSESSION=<id>; Path=/; SameSite=Lax`,
sin `HttpOnly` ni `Secure`. En el navegador, `document.cookie` muestra el id de sesión.

Consecuencias:

- **Sin `HttpOnly`:** cualquier script de la página lee la sesión. Combinado con los
  XSS del sistema, el atacante roba la sesión de un cajero o del administrador
  (Spoofing, Elevation of privilege).
- **Sin `Secure`:** la cookie viaja también por HTTP en claro; cualquiera en la red de
  la tienda puede capturarla (Information disclosure).
- **`timeout: 30d` + `persistent: true`:** una sesión robada sigue siendo válida un mes
  sin uso y sobrevive a los reinicios del servidor, porque Tomcat serializa las
  sesiones a disco al apagarse y las restaura al arrancar.

OWASP A07 — Identification and Authentication Failures.

## Decisión

Se endurece la configuración de la sesión en `application.yml`:

```yaml
servlet:
  session:
    cookie:
      name: PVSESSION
      http-only: true
      secure: true
      same-site: strict
    timeout: 15m
    persistent: false
```

| Atributo | Valor | Por qué |
|---|---|---|
| `http-only` | `true` | `document.cookie` deja de exponer el id; un XSS ya no puede leerlo directamente. |
| `secure` | `true` | El navegador solo envía la cookie por HTTPS. |
| `same-site` | `strict` | El frontend llama a la API por el mismo origen (proxy `/api` de nginx y de Vite), así que no se necesita enviar la cookie en navegación entre sitios. `Strict` además reduce el CSRF mientras 1.9 siga abierto. |
| `timeout` | `15m` | Expiración por inactividad dentro del rango que recomienda OWASP para aplicaciones con datos de pago. |
| `persistent` | `false` | Un reinicio del servidor invalida todas las sesiones. |
| `max-age` | (sin definir) | La cookie es de sesión del navegador: se borra al cerrarlo. |

## Alternativas consideradas

| Opción | Pros | Contras |
|---|---|---|
| Fijar los atributos en código (`CookieSerializer`/`ServletContextInitializer`) | Más difícil de deshacer por accidente | Duplica lo que Spring Boot ya ofrece por propiedades; dos lugares que mantener |
| `same-site: lax` | Permite llegar con sesión desde un enlace externo | No hay ningún flujo que lo necesite; `Strict` es más restrictivo sin costo |
| `timeout: 30m` (valor por defecto de Spring) | Menos reautenticaciones para el cajero | Duplica la ventana de uso de una sesión robada en un sistema con pagos |
| **Propiedades `server.servlet.session.*` (elegida)** | Cambio declarativo, en el mismo lugar donde estaba la falla; lo aplica el contenedor a toda cookie de sesión | Depende de que el archivo no se vuelva a relajar (lo cubre la prueba) |

## Consecuencias

- **Positivas:**
    - La cabecera pasa a ser `Set-Cookie: PVSESSION=<id>; Path=/; Secure; HttpOnly; SameSite=Strict`.
    - Una sesión robada caduca a los 15 minutos sin uso y no sobrevive a un reinicio.
- **Negativas / costos:**
    - **`Secure` exige HTTPS.** Los navegadores tratan `http://localhost` como contexto
      seguro, así que el entorno de desarrollo (`localhost:5173` / `localhost:8080`)
      sigue funcionando. Si se entra por la IP de la red (`http://192.168.x.x:5173`),
      el navegador descarta la cookie y el login no se mantiene: en la tienda hay que
      servir el frontend por HTTPS (terminación TLS en nginx, control 5.6).
    - El cajero tiene que volver a iniciar sesión tras 15 minutos de inactividad.
    - **No cierra todo el robo de sesión.** `HttpOnly` impide leer la cookie, pero el id
      sigue saliendo en el cuerpo de `POST /api/auth/login` (`sessionId`) y de
      `GET /api/auth/sesion`; un XSS todavía puede obtenerlo por ahí (control 6.7).
      Tampoco se corrigen la fijación de sesión (6.5), el logout que no invalida la
      sesión (6.6) ni HTTP Basic (6.8). Son hallazgos aparte de la misma familia.

- **Prueba que demuestra el control:** `backend/src/test/java/com/curso/pv/config/CookieDeSesionTest.java`
    - Lee el `application.yml` real, lo aplica a un Tomcat embebido con el mismo
      customizer que usa Spring Boot y hace una petición que crea la sesión (como el
      login). Inspecciona el `Set-Cookie` que llega al cliente, igual que el `curl`
      del reporte, sin necesitar MySQL.
    - **Antes (rojo):** 5 de 7 pruebas fallan. La cookie llega como
      `["path=/", "samesite=lax"]` (sin `httponly` ni `secure`), el timeout es `720H`
      en vez de `15M` y `persistent` es `true`.
    - **Después (verde):** 7/7. Comando: `./mvnw test -Dtest=CookieDeSesionTest`.
    - Para reproducir el rojo: restaurar los cinco valores originales en `application.yml`.
