# ADR-0003 · La API nunca devuelve el campo password

- **Estado:** Aceptado
- **Fecha:** 11/17/2026
- **Autor(es):** Lucia Vasquez
- **Hallazgos relacionados:** DATA-03

## Contexto

`UsuarioControlador`, `UsuarioServicio` y `AuthControlador.login` serializaban la
entidad `Usuario` completa o el objeto `Authentication` de Spring Security, ambos
con la contraseña incluida:

```java
cuerpo.put("credenciales", autenticacion.getCredentials());
cuerpo.put("principal", autenticacion.getPrincipal());
```

Se verificó: `GET /api/usuarios` devuelve `password` para cada usuario, y
`POST /api/auth/login` devuelve la contraseña ingresada (`credenciales`) y el
hash almacenado dentro de `principal`. Cualquier cuenta con sesión —no solo
ADMIN— puede leer la contraseña de todas las demás, incluidas las de
administradores.

Esto es independiente de ADR-0002: aunque la contraseña ya esté hasheada
(BCrypt), seguir exponiéndola permite un ataque de fuerza bruta offline contra
el hash, fuera de cualquier límite de intentos del login.

## Decisión

Se introduce `UsuarioDTO`, un record sin el campo `password`, y es lo único
que sale de la API:

```java
public record UsuarioDTO(Long id, String username, String nombre, String email, String rol, Boolean activo) {
    public static UsuarioDTO desde(Usuario usuario) { ... }
}
```

- `UsuarioServicio` y `UsuarioControlador` devuelven `UsuarioDTO`/`List<UsuarioDTO>`
  en vez de la entidad.
- `AuthServicio.registrar` devuelve `UsuarioDTO.desde(guardado)` en el campo `usuario`.
- `AuthControlador.login` deja de incluir `principal` y `credenciales` en la respuesta.
- La auditoría (`ServicioAuditoria`) deja de recibir la contraseña, en claro o
  hasheada, desde `AuthServicio.registrar`, `UsuarioServicio.crear`,
  `UsuarioServicio.actualizar` y `UsuarioServicio.cambiarPassword`.

## Alternativas consideradas

| Opción | Pros | Contras |
|---|---|---|
| `@JsonIgnore` en `Usuario.password` | Cambio de una línea | Afecta también la deserialización de entrada si no se separa lectura/escritura; sigue acoplando la API a la entidad JPA |
| **DTO explícito sin el campo (elegida)** | Separa el contrato de la API del modelo de persistencia; imposible olvidar el campo en un controlador nuevo si se sigue el mismo patrón | Hay que mapear manualmente (o con un mapper) en cada punto de salida |

## Consecuencias

- **Positivas:**
    - Ninguna respuesta de la API vuelve a incluir el campo `password`, ni en claro
      ni hasheado.
    - La tabla `auditoria` y los logs del contenedor dejan de acumular contraseñas.
- **Negativas / costos:**
    - No corrige que `UsuarioControlador` siga sin exigir rol ADMIN (BAC-03) ni que
      el registro siga aceptando un `rol` elegido por el cliente (BAC-04): quien
      pueda llamar a estos endpoints sigue pudiendo leer y modificar usuarios
      ajenos, solo que ya no ve la contraseña de nadie.
    - `/api/auth/sesion` sigue exponiendo otros datos de la sesión (id, cookie,
      versión del servidor); es un hallazgo de la familia de gestión de sesiones,
      fuera de este fix.

- **Prueba que demuestra el control:**
    - Antes: el JSON de `GET /api/usuarios` y de `POST /api/auth/login` contiene
      la clave `"password"` (o `"credenciales"`/`"principal"`).
    - Después: ninguna de las dos respuestas contiene esa información.
    - (Agreguen aquí su captura antes/después.)