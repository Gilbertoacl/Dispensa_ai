package dev.gilberto.gestaousuarios.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/** Habilita tarefas agendadas (limpeza de contadores e janelas). */
@Configuration
@EnableScheduling
public class AgendamentoConfig {
}
