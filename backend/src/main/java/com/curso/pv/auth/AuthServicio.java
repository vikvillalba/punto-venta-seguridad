package com.curso.pv.auth;

import com.curso.pv.log.ServicioAuditoria;
import com.curso.pv.usuario.Usuario;
import com.curso.pv.usuario.UsuarioConsultasInseguras;
import com.curso.pv.usuario.UsuarioRepositorio;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

@Service
public class AuthServicio {

    private final UsuarioRepositorio usuarios;
    private final UsuarioConsultasInseguras consultas;
    private final ServicioAuditoria auditoria;

    public AuthServicio(UsuarioRepositorio usuarios,
                        UsuarioConsultasInseguras consultas,
                        ServicioAuditoria auditoria) {
        this.usuarios = usuarios;
        this.consultas = consultas;
        this.auditoria = auditoria;
    }

    /** FIX: el rol de un auto-registro lo decide el servidor, nunca el cliente. */
    static final String ROL_POR_DEFECTO = "VENDEDOR";

    // FIX (escalada de privilegios): recibe un RegistroDTO ya validado, que no tiene campo "rol"
    @Transactional
    public Map<String, Object> registrar(RegistroDTO datos, HttpServletRequest request) {
        Map<String, Object> respuesta = new HashMap<>();

        String username = datos.username().trim();
        String password = datos.password();

        // VULNERABILIDAD (SQLi): comprobacion de duplicados concatenando el valor
        Usuario existente = consultas.porUsername(username);
        if (existente != null) {
            respuesta.put("error", "El usuario ya existe");
            return respuesta;
        }

        Usuario usuario = new Usuario();
        usuario.setUsername(username);
        // VULNERABILIDAD: password en texto plano
        usuario.setPassword(password);
        usuario.setNombre(datos.nombre() != null && !datos.nombre().isBlank() ? datos.nombre().trim() : username);
        usuario.setEmail(datos.email() != null && !datos.email().isBlank() ? datos.email().trim() : null);
        // FIX (escalada de privilegios): el rol siempre lo fija el servidor
        usuario.setRol(ROL_POR_DEFECTO);
        usuario.setActivo(true);

        Usuario guardado = usuarios.save(usuario);

        auditoria.registrar(guardado.getId(), guardado.getUsername(), "REGISTRO", "USUARIO",
                guardado.getId(),
                Map.of("username", guardado.getUsername(), "rol", guardado.getRol()), request);

        respuesta.put("mensaje", "Usuario registrado");
        respuesta.put("usuario", guardado);
        return respuesta;
    }
}