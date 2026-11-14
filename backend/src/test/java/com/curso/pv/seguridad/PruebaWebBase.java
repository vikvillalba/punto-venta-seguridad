package com.curso.pv.seguridad;

import com.curso.pv.auth.AuthControlador;
import com.curso.pv.auth.AuthServicio;
import com.curso.pv.common.ManejadorGlobalDeErrores;
import com.curso.pv.config.SecurityConfig;
import com.curso.pv.log.ServicioAuditoria;
import com.curso.pv.pago.PagoControlador;
import com.curso.pv.pago.PagoServicio;
import com.curso.pv.producto.ProductoControlador;
import com.curso.pv.producto.ProductoRepositorio;
import com.curso.pv.producto.ProductoServicio;
import com.curso.pv.security.UsuarioActual;
import com.curso.pv.security.UsuariosDetailsService;
import com.curso.pv.usuario.Usuario;
import com.curso.pv.usuario.UsuarioConsultasInseguras;
import com.curso.pv.usuario.UsuarioControlador;
import com.curso.pv.usuario.UsuarioRepositorio;
import com.curso.pv.usuario.UsuarioServicio;
import com.curso.pv.venta.MovimientoConsultasInseguras;
import com.curso.pv.venta.MovimientoInventarioRepositorio;
import com.curso.pv.venta.Venta;
import com.curso.pv.venta.VentaConsultasInseguras;
import com.curso.pv.venta.VentaControlador;
import com.curso.pv.venta.VentaItemRepositorio;
import com.curso.pv.venta.VentaRepositorio;
import com.curso.pv.venta.VentaServicio;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.math.BigDecimal;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

/**
 * Contexto web real (SecurityConfig + controladores + servicios de auth/ventas)
 * con la capa de datos simulada: no necesita MySQL.
 *
 * Usuarios de prueba:
 *   admin   (id 1, ADMIN)
 *   vendedor(id 2, VENDEDOR)  -> dueno de la venta 10
 *   ana     (id 3, VENDEDOR)  -> duena de la venta 20
 */
@SpringJUnitWebConfig(PruebaWebBase.Contexto.class)
abstract class PruebaWebBase {

    @Configuration
    @EnableWebMvc
    @Import({SecurityConfig.class, ManejadorGlobalDeErrores.class, UsuariosDetailsService.class, UsuarioActual.class,
            AuthControlador.class, AuthServicio.class,
            VentaControlador.class, VentaServicio.class,
            PagoControlador.class, UsuarioControlador.class, ProductoControlador.class})
    static class Contexto {
    }

    static final String PASSWORD = "secreto123";
    static final long VENTA_DEL_VENDEDOR = 10L;
    static final long VENTA_DE_ANA = 20L;

    // Capa de datos simulada
    @MockitoBean UsuarioConsultasInseguras consultasUsuario;
    @MockitoBean UsuarioRepositorio usuarioRepositorio;
    @MockitoBean ServicioAuditoria auditoria;
    @MockitoBean VentaRepositorio ventaRepositorio;
    @MockitoBean VentaConsultasInseguras ventaConsultas;
    @MockitoBean VentaItemRepositorio ventaItemRepositorio;
    @MockitoBean ProductoRepositorio productoRepositorio;
    @MockitoBean MovimientoInventarioRepositorio movimientoRepositorio;
    @MockitoBean MovimientoConsultasInseguras movimientoConsultas;
    // Servicios que no se prueban aqui
    @MockitoBean PagoServicio pagoServicio;
    @MockitoBean UsuarioServicio usuarioServicio;
    @MockitoBean ProductoServicio productoServicio;

    @Autowired
    WebApplicationContext contexto;

    MockMvc mvc;

    @BeforeEach
    void prepararBase() {
        mvc = MockMvcBuilders.webAppContextSetup(contexto).apply(springSecurity()).build();

        when(consultasUsuario.porUsername(anyString())).thenReturn(null);
        when(consultasUsuario.porUsername("admin")).thenReturn(usuario(1L, "admin", "ADMIN"));
        when(consultasUsuario.porUsername("vendedor")).thenReturn(usuario(2L, "vendedor", "VENDEDOR"));
        when(consultasUsuario.porUsername("ana")).thenReturn(usuario(3L, "ana", "VENDEDOR"));

        when(ventaRepositorio.findById(VENTA_DEL_VENDEDOR)).thenReturn(Optional.of(venta(VENTA_DEL_VENDEDOR, 2L)));
        when(ventaRepositorio.findById(VENTA_DE_ANA)).thenReturn(Optional.of(venta(VENTA_DE_ANA, 3L)));
        when(ventaRepositorio.save(any(Venta.class))).thenAnswer(inv -> {
            Venta v = inv.getArgument(0);
            if (v.getId() == null) {
                v.setId(99L);
            }
            return v;
        });
        when(usuarioRepositorio.save(any(Usuario.class))).thenAnswer(inv -> {
            Usuario u = inv.getArgument(0);
            u.setId(50L);
            return u;
        });
    }

    /** Sesion autenticada con la autoridad que genera la app (ROL_<rol>). */
    static RequestPostProcessor como(String username, String rol) {
        return SecurityMockMvcRequestPostProcessors.user(username)
                .authorities(new SimpleGrantedAuthority("ROL_" + rol));
    }

    static Usuario usuario(Long id, String username, String rol) {
        Usuario u = new Usuario();
        u.setId(id);
        u.setUsername(username);
        u.setPassword(PASSWORD);
        u.setNombre(username);
        u.setRol(rol);
        u.setActivo(true);
        return u;
    }

    static Venta venta(Long id, Long usuarioId) {
        Venta v = new Venta();
        v.setId(id);
        v.setUsuarioId(usuarioId);
        v.setFolio("V-" + id);
        v.setTotal(new BigDecimal("100.00"));
        v.setEstado("COMPLETADA");
        return v;
    }
}
