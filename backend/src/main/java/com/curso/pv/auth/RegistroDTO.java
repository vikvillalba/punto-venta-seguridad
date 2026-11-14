package com.curso.pv.auth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * FIX (mass assignment / escalada de privilegios): DTO de entrada del registro.
 *
 * Solo expone los campos que el cliente puede decidir. NO tiene campo "rol"
 * (ni "activo", ni "id"): si el cliente los manda, Jackson los ignora y el
 * servidor asigna siempre el rol VENDEDOR. Se valida con @Valid en el controlador.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RegistroDTO(
        @NotBlank(message = "El usuario es obligatorio")
        @Size(min = 3, max = 50, message = "El usuario debe tener entre 3 y 50 caracteres")
        @Pattern(regexp = "^[A-Za-z0-9._-]+$", message = "El usuario solo admite letras, numeros, '.', '_' y '-'")
        String username,

        @NotBlank(message = "La contrasena es obligatoria")
        @Size(min = 8, max = 100, message = "La contrasena debe tener entre 8 y 100 caracteres")
        String password,

        @Size(max = 100, message = "El nombre admite como maximo 100 caracteres")
        String nombre,

        @Email(message = "El email no es valido")
        @Size(max = 150, message = "El email admite como maximo 150 caracteres")
        String email
) {
}
