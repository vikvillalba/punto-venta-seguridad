package com.curso.pv.seguridad;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Fix 1: RBAC (autorizacion por rol en SecurityConfig) y control de acceso a
 * nivel de objeto / BOLA (VentaServicio y PagoControlador).
 *
 * Si se quita la defensa (p. ej. .anyRequest().permitAll() o se borra exigirAcceso),
 * estas pruebas pasan a rojo.
 */
class ControlDeAccesoTest extends PruebaWebBase {

    // ---------------- RBAC ----------------

    @Test
    @DisplayName("RBAC: sin sesion, la API de ventas responde 401")
    void anonimoNoPuedeVerVentas() throws Exception {
        mvc.perform(get("/api/ventas")).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("RBAC: un VENDEDOR no puede listar usuarios (403)")
    void vendedorNoPuedeListarUsuarios() throws Exception {
        mvc.perform(get("/api/usuarios").with(como("vendedor", "VENDEDOR")))
                .andExpect(status().isForbidden());
        verify(usuarioServicio, never()).listar();
    }

    @Test
    @DisplayName("RBAC: un ADMIN si puede listar usuarios (200)")
    void adminPuedeListarUsuarios() throws Exception {
        mvc.perform(get("/api/usuarios").with(como("admin", "ADMIN")))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("RBAC: un VENDEDOR no puede anular ventas (403)")
    void vendedorNoPuedeAnularVentas() throws Exception {
        mvc.perform(post("/api/ventas/{id}/anular", VENTA_DEL_VENDEDOR).with(como("vendedor", "VENDEDOR")))
                .andExpect(status().isForbidden());
        verify(ventaRepositorio, never()).save(any());
    }

    @Test
    @DisplayName("RBAC: un VENDEDOR no puede ver las tarjetas de todos los pagos (403)")
    void vendedorNoPuedeListarPagos() throws Exception {
        mvc.perform(get("/api/pagos").with(como("vendedor", "VENDEDOR")))
                .andExpect(status().isForbidden());
        verify(pagoServicio, never()).listar();
    }

    @Test
    @DisplayName("RBAC: un VENDEDOR no puede borrar productos (403)")
    void vendedorNoPuedeBorrarProductos() throws Exception {
        mvc.perform(delete("/api/productos/{id}", 1).with(como("vendedor", "VENDEDOR")))
                .andExpect(status().isForbidden());
        verify(productoServicio, never()).eliminar(any());
    }

    // ---------------- BOLA ----------------

    @Test
    @DisplayName("BOLA: un vendedor no puede ver la venta de otro vendedor (403)")
    void vendedorNoPuedeVerVentaAjena() throws Exception {
        mvc.perform(get("/api/ventas/{id}", VENTA_DE_ANA).with(como("vendedor", "VENDEDOR")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("BOLA: un vendedor no puede ver los items de una venta ajena (403)")
    void vendedorNoPuedeVerItemsDeVentaAjena() throws Exception {
        mvc.perform(get("/api/ventas/{id}/items", VENTA_DE_ANA).with(como("vendedor", "VENDEDOR")))
                .andExpect(status().isForbidden());
        verify(ventaItemRepositorio, never()).porVenta(any());
    }

    @Test
    @DisplayName("BOLA: un vendedor no puede cobrar una venta ajena (403)")
    void vendedorNoPuedeCobrarVentaAjena() throws Exception {
        mvc.perform(post("/api/pagos/procesar").with(como("vendedor", "VENDEDOR"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ventaId\": " + VENTA_DE_ANA + ", \"metodo\": \"EFECTIVO\"}"))
                .andExpect(status().isForbidden());
        verify(pagoServicio, never()).procesar(any());
    }

    @Test
    @DisplayName("BOLA: el vendedor si puede ver su propia venta (200)")
    void vendedorPuedeVerSuVenta() throws Exception {
        mvc.perform(get("/api/ventas/{id}", VENTA_DEL_VENDEDOR).with(como("vendedor", "VENDEDOR")))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("BOLA: el admin puede ver cualquier venta (200)")
    void adminPuedeVerCualquierVenta() throws Exception {
        mvc.perform(get("/api/ventas/{id}", VENTA_DE_ANA).with(como("admin", "ADMIN")))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("BOLA: al listar, el vendedor solo recibe sus ventas")
    void listarSoloDevuelveVentasPropias() throws Exception {
        mvc.perform(get("/api/ventas").with(como("vendedor", "VENDEDOR")))
                .andExpect(status().isOk());
        verify(ventaRepositorio).findByUsuarioId(2L);
        verify(ventaRepositorio, never()).findAll();
    }
}
