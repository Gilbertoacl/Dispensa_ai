package dev.gilberto.gestaousuarios.usuario;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/** Corpo de {@code PUT /v1/usuarios/{id}/perfil}: valor ausente ou diferente de ADMIN/USER gera 400. */
public record AlterarPerfilRequest(
        @NotBlank(message = "{perfil.invalido}")
        @Pattern(regexp = "ADMIN|USER", message = "{perfil.invalido}")
        String perfil
) {}
