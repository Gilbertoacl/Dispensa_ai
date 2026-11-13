package dev.gilberto.gestaousuarios.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

/**
 * Configuração da documentação OpenAPI da feature de gestão de usuários e autenticação
 * (R14.1, R14.3).
 *
 * <p>Expõe os metadados da API (título, versão e descrição) e registra o esquema de segurança
 * HTTP <em>bearer</em> baseado em JWT. O esquema {@code bearer-jwt} é declarado em
 * {@link Components} e adicionado como requisito de segurança global, de modo que os endpoints
 * protegidos apareçam no Swagger UI exigindo o cabeçalho {@code Authorization: Bearer <token>}
 * (R14.3).
 *
 * <p>As rotas públicas (cadastro e login) continuam acessíveis sem token graças às regras
 * definidas em {@link SecurityConfig}; o requisito global apenas documenta o fluxo de
 * autenticação esperado para as demais operações.
 */
@Configuration
public class OpenApiConfig {

    /**
     * Nome do esquema de segurança bearer JWT, referenciado tanto no registro em
     * {@link Components} quanto no {@link SecurityRequirement} global.
     */
    private static final String ESQUEMA_BEARER_JWT = "bearer-jwt";

    /** Descrição da API, incluindo sessão, trade-off da D2 e limitação da D4 (R5.9, R9.10). */
    private static final String DESCRICAO = """
            API de cadastro, autenticação e gestão de usuários do Dispensa.ai.

            **Sessão.** O login devolve um access token JWT de curta duração (15 minutos) e um \
            refresh token opaco e rotativo: cada renovação (`POST /v1/auth/refresh`) invalida o \
            refresh anterior e emite um novo par. A reutilização de um refresh já consumido \
            revoga toda a família de sessões. `POST /v1/auth/logout` encerra a sessão atual e \
            `POST /v1/auth/logout-all` encerra todas as sessões do usuário.

            **Revogação imediata (Decisão D2).** O access token carrega a versão do usuário (`tv`). \
            A cada requisição protegida o servidor compara essa versão com a armazenada, o que \
            custa uma leitura por chave primária por requisição, em troca de revogação imediata \
            após troca de senha, alteração de perfil, exclusão ou logout-all. Tokens com `tv` \
            desatualizado recebem 401.

            **Limite de tentativas (Decisão D4).** O controle de taxa (HTTP 429 com cabeçalho \
            `Retry-After`) é mantido na memória do processo. Ele vale apenas para uma instância \
            única: com várias instâncias, cada uma conta separadamente. A evolução prevista é \
            mover o contador para um armazenamento compartilhado, como o Redis.

            **Erros.** 400 (validação), 401 (não autenticado ou token inválido/revogado), \
            403 (sem permissão), 404 (recurso inexistente), 409 (conflito) e 429 (limite excedido).

            **Segurança.** Endpoints públicos (cadastro, login e refresh) não exigem bearer; \
            os demais exigem o esquema `bearer-jwt`.""";

    /**
     * Define o documento OpenAPI da API com metadados e o esquema de segurança bearer JWT.
     *
     * @return o {@link OpenAPI} customizado com info, componentes de segurança e requisito global
     */
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Gestão de Usuários e Autenticação API")
                        .version("v1")
                        .description(DESCRICAO))
                .components(new Components()
                        .addSecuritySchemes(ESQUEMA_BEARER_JWT, new SecurityScheme()
                                .name(ESQUEMA_BEARER_JWT)
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")))
                .addSecurityItem(new SecurityRequirement().addList(ESQUEMA_BEARER_JWT));
    }
}
