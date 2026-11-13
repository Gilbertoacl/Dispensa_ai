package dev.gilberto.gestaousuarios.usuario;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record TrocarSenhaRequest(
        @NotBlank(message = "{password.obrigatorio}")
        String senhaAtual,
        @NotBlank(message = "{password.obrigatorio}")
        @Size(min = 8, max = 64, message = "{password.tamanho}")
        String novaSenha
) {}
