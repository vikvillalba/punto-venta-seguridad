package com.curso.pv.seguridad;

import com.curso.pv.usuario.Usuario;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Fix 2: registro con RegistroDTO + @Valid.
 *
 * Si se vuelve a recibir un Map (o se agrega "rol" al DTO, o se quita @Valid),
 * estas pruebas pasan a rojo.
 */
class RegistroTest extends PruebaWebBase {

    @Test
    @DisplayName("Registro: enviar \"rol\":\"ADMIN\" NO da privilegios; se guarda como VENDEDOR")
    void elRolNoSePuedeInyectar() throws Exception {
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"mallory","password":"password123","nombre":"Mallory",
                                 "email":"mallory@example.com","rol":"ADMIN"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.usuario.rol").value("VENDEDOR"));

        ArgumentCaptor<Usuario> guardado = ArgumentCaptor.forClass(Usuario.class);
        verify(usuarioRepositorio).save(guardado.capture());
        assertThat(guardado.getValue().getRol()).isEqualTo("VENDEDOR");
    }

    @Test
    @DisplayName("Registro: un registro valido sin rol funciona (camino feliz)")
    void registroValido() throws Exception {
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"nuevo\",\"password\":\"password123\",\"nombre\":\"Nuevo\",\"email\":\"\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mensaje").value("Usuario registrado"));
    }

    @Test
    @DisplayName("Registro: username vacio -> 400 y no se guarda nada")
    void usernameVacioEsRechazado() throws Exception {
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"\",\"password\":\"password123\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.campos.username").exists());
        verify(usuarioRepositorio, never()).save(any());
    }

    @Test
    @DisplayName("Registro: password demasiado corta -> 400 y no se guarda nada")
    void passwordCortaEsRechazada() throws Exception {
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"corto\",\"password\":\"123\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.campos.password").exists());
        verify(usuarioRepositorio, never()).save(any());
    }

    @Test
    @DisplayName("Registro: username con caracteres de inyeccion -> 400")
    void usernameConInyeccionEsRechazado() throws Exception {
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"x' OR '1'='1\",\"password\":\"password123\"}"))
                .andExpect(status().isBadRequest());
        verify(usuarioRepositorio, never()).save(any());
    }

    @Test
    @DisplayName("Registro: email invalido -> 400")
    void emailInvalidoEsRechazado() throws Exception {
        mvc.perform(post("/api/auth/registro").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"pepe\",\"password\":\"password123\",\"email\":\"no-es-email\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.campos.email").exists());
        verify(usuarioRepositorio, never()).save(any());
    }
}
