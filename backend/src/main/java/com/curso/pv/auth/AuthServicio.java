package com.curso.pv.auth;

import com.curso.pv.log.ServicioAuditoria;
import com.curso.pv.usuario.Usuario;
import com.curso.pv.usuario.UsuarioConsultasInseguras;
import com.curso.pv.usuario.UsuarioDTO;
import com.curso.pv.usuario.UsuarioRepositorio;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

@Service
public class AuthServicio {

    private final UsuarioRepositorio usuarios;
    private final UsuarioConsultasInseguras consultas;
    private final ServicioAuditoria auditoria;
    private final PasswordEncoder passwordEncoder;

    public AuthServicio(UsuarioRepositorio usuarios,
                        UsuarioConsultasInseguras consultas,
                        ServicioAuditoria auditoria,
                        PasswordEncoder passwordEncoder) {
        this.usuarios = usuarios;
        this.consultas = consultas;
        this.auditoria = auditoria;
        this.passwordEncoder = passwordEncoder;
    }

    // VULNERABILIDAD (BAC-04): el rol lo sigue decidiendo el cliente; es otro hallazgo
    @Transactional
    public Map<String, Object> registrar(Map<String, String> datos, HttpServletRequest request) {
        Map<String, Object> respuesta = new HashMap<>();

        String username = datos.get("username");
        String password = datos.get("password");
        String rol = datos.getOrDefault("rol", "VENDEDOR");

        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            respuesta.put("error", "Faltan datos de registro");
            return respuesta;
        }

        // VULNERABILIDAD (SQLi): fuera del alcance de este fix
        Usuario existente = consultas.porUsername(username);
        if (existente != null) {
            respuesta.put("error", "El usuario ya existe");
            return respuesta;
        }

        Usuario usuario = new Usuario();
        usuario.setUsername(username);
        // CORRECCION CRY-03: se hashea antes de guardar
        usuario.setPassword(passwordEncoder.encode(password));
        usuario.setNombre(datos.getOrDefault("nombre", username));
        usuario.setEmail(datos.get("email"));
        usuario.setRol(rol);
        usuario.setActivo(true);

        Usuario guardado = usuarios.save(usuario);

        // CORRECCION DATA-03: se audita sin la contrasena en claro que llego en "datos"
        Map<String, Object> detalleAuditoria = new HashMap<>(datos);
        detalleAuditoria.remove("password");
        auditoria.registrar(guardado.getId(), guardado.getUsername(), "REGISTRO", "USUARIO",
                guardado.getId(), detalleAuditoria, request);

        respuesta.put("mensaje", "Usuario registrado");
        // CORRECCION DATA-03: se devuelve el DTO, nunca la entidad con el hash
        respuesta.put("usuario", UsuarioDTO.desde(guardado));
        return respuesta;
    }
}