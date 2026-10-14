package dev.gilberto.gestaousuarios.shared.exceptions;

import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.List;

public record ErroResponse(
        LocalDateTime timestamp,
        int status,
        String erro,
        String mensagem,
        String path,
        List<CampoErro> camposComErro
) {
    public record CampoErro(String campo, String mensagem) {}

    public static ErroResponse of(HttpStatus status, String msg, String path) {
        return new ErroResponse(LocalDateTime.now(), status.value(), status.getReasonPhrase(), msg, path, null );
    }
}
