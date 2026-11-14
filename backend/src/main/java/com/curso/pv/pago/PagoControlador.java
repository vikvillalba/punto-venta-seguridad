package com.curso.pv.pago;

import com.curso.pv.venta.VentaServicio;   // FIX
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletResponse;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/pagos")
// RBAC: las rutas GET /api/pagos, /tarjeta y /configuracion exigen ROL_ADMIN (ver SecurityConfig).
// BOLA: procesar y porVenta verifican que la venta sea del usuario en sesion (o que sea admin).
public class PagoControlador {

    private final PagoServicio servicio;
    private final VentaServicio ventaServicio;   // FIX

    public PagoControlador(PagoServicio servicio, VentaServicio ventaServicio) {   // FIX
        this.servicio = servicio;
        this.ventaServicio = ventaServicio;
    }

    @PostMapping("/procesar")
    public Map<String, Object> procesar(@RequestBody Map<String, Object> datos) {
        // FIX (BOLA): solo se puede cobrar una venta propia (el admin puede cobrar cualquiera)
        ventaServicio.verificarAcceso(Long.valueOf(String.valueOf(datos.get("ventaId"))));
        return servicio.procesar(datos);
    }

    // VULNERABILIDAD: devuelve PAN y CVV de todas las tarjetas
    @GetMapping
    public List<Pago> listar() {
        return servicio.listar();
    }

    @GetMapping("/venta/{ventaId}")
    public List<Pago> porVenta(@PathVariable Long ventaId) {
        ventaServicio.verificarAcceso(ventaId);   // FIX (BOLA)
        return servicio.porVenta(ventaId);
    }

    // VULNERABILIDAD: permite enumerar tarjetas por numero completo
    @GetMapping("/tarjeta")
    public List<?> porTarjeta(@RequestParam String numero) {
        return servicio.porTarjeta(numero);
    }

    // VULNERABILIDAD: la credencial de la pasarela se "cachea" en una cookie
    // HttpOnly ("protegida"). No se puede leer con document.cookie desde la pantalla,
    // pero viaja en claro en la cabecera Set-Cookie: hay que interceptar la respuesta
    // con un proxy (Burp Suite / ZAP) para capturarla. El cuerpo ya no la devuelve.
    @GetMapping("/configuracion")
    public Map<String, Object> configuracion(HttpServletResponse respuesta) {
        Map<String, Object> cfg = servicio.configuracionPasarela();

        String apiKey = String.valueOf(cfg.remove("apiKey"));
        // Cookie "protegida": HttpOnly (invisible a JS), sin Secure (viaja en claro).
        respuesta.addHeader("Set-Cookie",
                "pv_gw=" + apiKey + "; Path=/; HttpOnly; SameSite=Lax");

        return cfg;
    }
}