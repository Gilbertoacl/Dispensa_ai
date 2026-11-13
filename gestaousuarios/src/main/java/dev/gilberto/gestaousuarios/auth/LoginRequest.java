package dev.gilberto.gestaousuarios.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank(message = "{email.obrigatorio}")
        @Email(message = "{email.invalido}")
        String email,
        @NotBlank(message = "{password.obrigatorio}")
        String senha
){
    @Override
    public String toString() {
        return "LoginRequest[email=" + email + ", senha=***]";
    }
}
