package com.curso.pv.usuario;

import com.curso.pv.security.UsuarioActual;
import com.curso.pv.log.ServicioAuditoria;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class UsuarioServicio {

    private final UsuarioRepositorio repositorio;
    private final UsuarioConsultasInseguras consultas;
    private final ServicioAuditoria auditoria;
    private final UsuarioActual usuarioActual;
    private final PasswordEncoder passwordEncoder;

    public UsuarioServicio(UsuarioRepositorio repositorio,
                           UsuarioConsultasInseguras consultas,
                           ServicioAuditoria auditoria,
                           UsuarioActual usuarioActual,
                           PasswordEncoder passwordEncoder) {
        this.repositorio = repositorio;
        this.consultas = consultas;
        this.auditoria = auditoria;
        this.usuarioActual = usuarioActual;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional(readOnly = true)
    public List<UsuarioDTO> listar() {
        // CORRECCION DATA-03: se mapea a DTO antes de salir del servicio
        return repositorio.findAll().stream().map(UsuarioDTO::desde).toList();
    }

    @Transactional(readOnly = true)
    public List<?> buscar(String texto) {
        // VULNERABILIDAD (SQLi): fuera del alcance de este fix
        return consultas.buscar(texto);
    }

    @Transactional(readOnly = true)
    public List<?> porRol(String rol) {
        return consultas.porRol(rol);
    }

    @Transactional(readOnly = true)
    public UsuarioDTO obtener(Long id) {
        // CORRECCION DATA-03: ya no se devuelve la entidad con la contrasena
        return UsuarioDTO.desde(repositorio.findById(id).orElse(null));
    }

    @Transactional
    public UsuarioDTO crear(Usuario usuario) {
        // CORRECCION CRY-03: se hashea antes de guardar
        usuario.setPassword(passwordEncoder.encode(usuario.getPassword()));
        Usuario guardado = repositorio.save(usuario);

        // CORRECCION DATA-03: la auditoria ya no recibe la contrasena, ni siquiera hasheada
        auditoria.registrar(usuarioActual.id(), usuarioActual.username(), "CREAR", "USUARIO",
                guardado.getId(), detalleSinPassword(guardado));
        return UsuarioDTO.desde(guardado);
    }

    @Transactional
    public UsuarioDTO actualizar(Long id, Usuario datos) {
        Usuario existente = repositorio.findById(id).orElse(null);
        if (existente == null) {
            return null;
        }
        existente.setUsername(datos.getUsername());
        // CORRECCION CRY-03: solo se toca el password si mandan uno nuevo; si no,
        // se conserva el hash existente (antes se sobreescribia siempre, incluso con null)
        if (datos.getPassword() != null && !datos.getPassword().isBlank()) {
            existente.setPassword(passwordEncoder.encode(datos.getPassword()));
        }
        existente.setNombre(datos.getNombre());
        existente.setEmail(datos.getEmail());
        // VULNERABILIDAD (BAC-03): sigue sin validar quien puede cambiar el rol; es otro hallazgo
        existente.setRol(datos.getRol());
        existente.setActivo(datos.getActivo());
        Usuario guardado = repositorio.save(existente);

        auditoria.registrar(usuarioActual.id(), usuarioActual.username(), "ACTUALIZAR", "USUARIO",
                id, detalleSinPassword(guardado));
        return UsuarioDTO.desde(guardado);
    }

    @Transactional
    public void eliminar(Long id) {
        // VULNERABILIDAD: no se valida que exista ni que el usuario tenga permisos (BAC, otro hallazgo)
        repositorio.deleteById(id);
        auditoria.registrar(usuarioActual.id(), usuarioActual.username(), "ELIMINAR", "USUARIO", id, Map.of("id", id));
    }

    @Transactional
    public void cambiarPassword(Long id, String nuevaPassword) {
        Usuario usuario = repositorio.findById(id).orElse(null);
        if (usuario == null) {
            return;
        }
        // CORRECCION CRY-03: se hashea la nueva contrasena
        usuario.setPassword(passwordEncoder.encode(nuevaPassword));
        repositorio.save(usuario);

        // CORRECCION DATA-03: ya no se escribe la contrasena (ni en claro ni hasheada) en la auditoria
        auditoria.registrar(usuarioActual.id(), usuarioActual.username(), "CAMBIAR_PASSWORD", "USUARIO",
                id, Map.of("id", id));
    }

    private Map<String, Object> detalleSinPassword(Usuario usuario) {
        Map<String, Object> detalle = new HashMap<>();
        detalle.put("id", usuario.getId());
        detalle.put("username", usuario.getUsername());
        detalle.put("nombre", usuario.getNombre());
        detalle.put("email", usuario.getEmail());
        detalle.put("rol", usuario.getRol());
        detalle.put("activo", usuario.getActivo());
        return detalle;
    }
}