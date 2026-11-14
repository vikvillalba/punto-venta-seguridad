package com.curso.pv.common;

import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ResponseStatus;

// VULNERABILIDAD: devuelve el stack trace completo y la clase de la excepcion al cliente
@RestControllerAdvice
public class ManejadorGlobalDeErrores {

    @ExceptionHandler(Exception.class)
    public Map<String, Object> manejar(Exception excepcion) {
        StringWriter buffer = new StringWriter();
        excepcion.printStackTrace(new PrintWriter(buffer));

        Map<String, Object> respuesta = new HashMap<>();
        respuesta.put("error", excepcion.getClass().getName());
        respuesta.put("mensaje", excepcion.getMessage());
        respuesta.put("stackTrace", buffer.toString());
        respuesta.put("causa", excepcion.getCause() != null ? excepcion.getCause().toString() : null);
        return respuesta;
    }

    // FIX (validacion): un DTO invalido (@Valid) responde 400 con los errores por campo,
    // en vez de caer en el handler generico (que respondia 200 con stack trace)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> datosInvalidos(MethodArgumentNotValidException excepcion) {
        Map<String, String> campos = new LinkedHashMap<>();
        excepcion.getBindingResult().getFieldErrors()
                .forEach(e -> campos.putIfAbsent(e.getField(), e.getDefaultMessage()));
        return Map.of("error", "Datos invalidos", "campos", campos);
    }

    // FIX (validacion): cuerpo JSON mal formado o con tipos incorrectos -> 400
    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> cuerpoIlegible(HttpMessageNotReadableException excepcion) {
        return Map.of("error", "Cuerpo de la peticion invalido");
    }

    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Map<String, Object> accesoDenegado(AccessDeniedException excepcion) {
        return Map.of("error", "Acceso denegado");
    }
}
