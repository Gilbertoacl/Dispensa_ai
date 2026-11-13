package dev.gilberto.gestaousuarios.usuario;

import jakarta.validation.constraints.NotBlank;

public record AtualizarPerfilRequest(
        @NotBlank(message = "{nome.obrigatorio}")
        String nome
) {}
