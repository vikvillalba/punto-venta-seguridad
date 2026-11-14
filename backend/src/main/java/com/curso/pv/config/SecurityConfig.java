package com.curso.pv.config;

import com.curso.pv.security.CodificadorEnClaro;
import com.curso.pv.security.UsuariosDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /** CodificadorEnClaro.autoridadesDe("ADMIN") genera "ROL_ADMIN" (con "ROL_", no "ROLE_"). */
    static final String ADMIN = "ROL_ADMIN";

    @Bean
    public SecurityFilterChain cadenaDeSeguridad(HttpSecurity http,
                                                 HttpSessionSecurityContextRepository contextoRepositorio) throws Exception {
        http
                // VULNERABILIDAD: sin proteccion CSRF
                .csrf(csrf -> csrf.disable())
                .cors(cors -> { })
                // VULNERABILIDAD: sin CSP ni demas cabeceras de seguridad
                .headers(headers -> { })

                // VULNERABILIDAD: la sesion no se renueva al iniciar sesion (session fixation)
                .sessionManagement(sesion -> sesion
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .sessionFixation(fixacion -> { }))

                // VULNERABILIDAD: se reutiliza la sesion existente sin validar su origen
                .securityContext(contexto -> contexto.securityContextRepository(contextoRepositorio))

                // FIX (RBAC): sin sesion -> 401 (evita el popup de Basic auth del navegador)
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))

                // FIX (RBAC, deny-by-default): lo no listado exige sesion; lo sensible exige ADMIN.
                // El orden importa: la primera regla que coincide gana.
                .authorizeHttpRequests(auth -> auth
                        // Publico: salud, login, registro, logout y estado de sesion
                        .requestMatchers("/error", "/api/salud").permitAll()
                        .requestMatchers(HttpMethod.POST,
                                "/api/auth/login", "/api/auth/registro", "/api/auth/logout").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/auth/yo").permitAll()

                        // Solo ADMIN: usuarios, reportes, integraciones, configuracion, diagnostico, actuator
                        .requestMatchers("/api/usuarios/**", "/api/reportes/**", "/api/integraciones/**",
                                "/api/configuracion/**", "/api/diagnostico", "/actuator/**").hasAuthority(ADMIN)

                        // Solo ADMIN: datos de tarjetas y credenciales de la pasarela
                        .requestMatchers(HttpMethod.GET,
                                "/api/pagos", "/api/pagos/tarjeta", "/api/pagos/configuracion").hasAuthority(ADMIN)

                        // Solo ADMIN: anular ventas, kardex y busquedas globales de ventas
                        .requestMatchers(HttpMethod.POST, "/api/ventas/*/anular").hasAuthority(ADMIN)
                        .requestMatchers("/api/ventas/inventario/**", "/api/ventas/buscar",
                                "/api/ventas/cliente/**").hasAuthority(ADMIN)

                        // Solo ADMIN: escritura de catalogo y borrado de clientes
                        .requestMatchers(HttpMethod.POST, "/api/productos", "/api/categorias").hasAuthority(ADMIN)
                        .requestMatchers(HttpMethod.PUT, "/api/productos/**").hasAuthority(ADMIN)
                        .requestMatchers(HttpMethod.DELETE,
                                "/api/productos/**", "/api/categorias/**", "/api/clientes/**").hasAuthority(ADMIN)

                        // Todo lo demas (vender, cobrar, ver catalogo, clientes): usuario autenticado
                        .anyRequest().authenticated())

                // VULNERABILIDAD: HTTP Basic habilitado, las credenciales viajan en cada peticion
                .httpBasic(basic -> { })
                .formLogin(form -> form.disable())
                .logout(logout -> logout.disable());

        return http.build();
    }

    @Bean
    public HttpSessionSecurityContextRepository contextoRepositorio() {
        // VULNERABILIDAD: la sesion se guarda tal cual en el contenedor, sin cifrar
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public SecurityContextRepository securityContextRepository(HttpSessionSecurityContextRepository repositorio) {
        return repositorio;
    }

    @Bean
    public DaoAuthenticationProvider proveedorDeAutenticacion(UsuariosDetailsService detailsService) {
        DaoAuthenticationProvider proveedor = new DaoAuthenticationProvider(detailsService);
        // VULNERABILIDAD: comparacion de contrasenas en texto plano
        proveedor.setPasswordEncoder(new CodificadorEnClaro());
        return proveedor;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}