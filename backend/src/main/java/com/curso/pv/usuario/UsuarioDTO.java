package com.curso.pv.usuario;

/**
 * CORRECCION DATA-03: la API nunca devuelve la entidad Usuario completa
 * (que incluye el hash de la contrasena). Este DTO es lo unico que sale
 * hacia el cliente.
 */
public record UsuarioDTO(Long id, String username, String nombre, String email, String rol, Boolean activo) {

    public static UsuarioDTO desde(Usuario usuario) {
        if (usuario == null) {
            return null;
        }
        return new UsuarioDTO(usuario.getId(), usuario.getUsername(), usuario.getNombre(),
                usuario.getEmail(), usuario.getRol(), usuario.getActivo());
    }
}