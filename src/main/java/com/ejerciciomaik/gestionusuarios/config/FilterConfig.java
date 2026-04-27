package com.ejerciciomaik.gestionusuarios.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.ejerciciomaik.gestionusuarios.filter.JwtValidationFilter;

@Configuration
public class FilterConfig {
    @Bean

    FilterRegistrationBean<JwtValidationFilter> jwtFilter(JwtValidationFilter jwtValidationFilter) {

        /**Creamos un contenedor de registro del bean para el filtro */
        FilterRegistrationBean<JwtValidationFilter> registrationBean = new FilterRegistrationBean<>();

        /**Es decirle a Spring que este filtro es el que quiero que trabaje */
        registrationBean.setFilter(jwtValidationFilter);

        /**Define el alcance del filtro, quiero que revise todas las peticiones que entren en el mi aop */
        registrationBean.addUrlPatterns("/*");

        /**Establewcemos la prioridad de ejecucio n de los filtros */
        registrationBean.setOrder(1);

        /**Retornamos en bean coonfigurado para que spring lo guarde en su contexto (inyeccion) */
        return registrationBean;
    }
}
