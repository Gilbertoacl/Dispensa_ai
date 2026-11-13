package dev.gilberto.gestaousuarios;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class GestaousuariosApplication {

	public static void main(String[] args) {
		SpringApplication.run(GestaousuariosApplication.class, args);
	}

}
