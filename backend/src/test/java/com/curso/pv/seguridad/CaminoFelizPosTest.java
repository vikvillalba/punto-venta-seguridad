package com.curso.pv.seguridad;

import com.curso.pv.venta.Venta;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * El camino feliz del POS debe seguir funcionando con los fixes:
 * login -> agregar al carrito -> vender (checkout) -> cobrar.
 */
class CaminoFelizPosTest extends PruebaWebBase {

    @Test
    @DisplayName("POS: un vendedor inicia sesion, vende y cobra su venta")
    void loginVenderCobrar() throws Exception {
        when(pagoServicio.procesar(any())).thenReturn(Map.of("estado", "APROBADO"));

        // 1. Login (cookie de sesion)
        MvcResult login = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"vendedor\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        MockHttpSession sesion = (MockHttpSession) login.getRequest().getSession(false);
        assertThat(sesion).isNotNull();

        mvc.perform(get("/api/auth/yo").session(sesion))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("vendedor"));

        // 2. Agregar al carrito
        mvc.perform(post("/api/ventas/carrito").session(sesion)
                        .param("productoId", "1").param("cantidad", "2").param("precio", "15.50"))
                .andExpect(status().isOk());

        // 3. Vender: aunque el body intente atribuir la venta a otro usuario, se usa el de la sesion
        mvc.perform(post("/api/ventas/checkout").session(sesion).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"usuarioId\": 1, \"observaciones\": \"mostrador\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.venta.id").value(99));

        ArgumentCaptor<Venta> venta = ArgumentCaptor.forClass(Venta.class);
        verify(ventaRepositorio, atLeastOnce()).save(venta.capture());
        assertThat(venta.getValue().getUsuarioId()).isEqualTo(2L);

        // 4. Cobrar la venta recien creada (es propia -> permitido)
        when(ventaRepositorio.findById(99L)).thenReturn(java.util.Optional.of(venta.getValue()));
        mvc.perform(post("/api/pagos/procesar").session(sesion).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ventaId\": 99, \"metodo\": \"EFECTIVO\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.estado").value("APROBADO"));
    }

    @Test
    @DisplayName("POS: login con password incorrecta no abre sesion")
    void loginIncorrecto() throws Exception {
        MvcResult resultado = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"vendedor\",\"password\":\"otra\"}"))
                .andReturn();
        assertThat(resultado.getResponse().getContentAsString()).doesNotContain("Sesion iniciada");
    }
}
