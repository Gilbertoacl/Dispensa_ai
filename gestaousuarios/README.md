# gestaousuarios

Microserviço de gestão de usuários e autenticação do Dispensa AI (Java 25, Spring Boot 4.1.1, PostgreSQL, Flyway).

Este documento descreve a sessão e os tokens, as decisões de projeto de segurança, a configuração e como rodar e testar.

## Sessão e tokens

O login devolve um par de tokens:

- **Access token**: JWT assinado (HMAC) de curta duração, 15 minutos por padrão (`access-expiration: 900` segundos; aceito de 600 a 900). Claims: `iss`, `iat`, `exp`, `sub` (id do usuário), `perfil` e `tv` (versão de token do usuário). Vai no cabeçalho `Authorization: Bearer <accessToken>`.
- **Refresh token**: valor opaco aleatório (32 bytes em Base64 URL, 43 caracteres), de uso único e rotativo. Só o hash SHA-256 é guardado no banco; o valor em claro é devolvido uma única vez. Validade padrão de 7 dias (aceito de 7 a 30 dias).

Resposta de `login` e `refresh` (`TokenResponse`): `accessToken`, `refreshToken`, `tokenType`, `expiraEm`, `refreshExpiraEm`.

### Fluxo de refresh, rotação e reuso

1. `POST /v1/auth/login` cria uma nova **família** de refresh tokens e devolve o primeiro par.
2. `POST /v1/auth/refresh` com o refresh token vigente consome esse token (rotação atômica), emite um novo refresh token na mesma família e um novo access token com o perfil e a `tv` atuais do usuário.
3. Se um refresh token já usado ou revogado for reapresentado, o serviço trata como **reuso**: revoga a família inteira (só ela, as demais sessões do usuário seguem válidas), registra o evento `REFRESH_REUSO_DETECTADO` e responde 401. O token legítimo mais novo da família também deixa de valer, e o usuário precisa fazer login de novo.
4. Refresh token expirado ou desconhecido responde 401.
5. Uma corrida legítima (duplo clique, duas abas usando o mesmo token) é tratada como reuso. É uma escolha estrita e deliberada.

### Encerramento de sessão

- `POST /v1/auth/logout` (público, recebe o refresh token): revoga a família do token. Responde 204, inclusive para token desconhecido.
- `POST /v1/auth/logout-all` (autenticado): revoga todas as sessões do usuário e incrementa a `tokenVersion`, invalidando também os access tokens já emitidos.

A `tokenVersion` do usuário também é incrementada na troca de senha e na alteração de perfil, e as sessões de refresh são revogadas junto.

## Decisões de projeto

### D1: refresh token opaco com hash no banco

O refresh token não é JWT. É um valor aleatório de 256 bits cujo hash SHA-256 fica na tabela `REFRESH_TOKENS`. Como a entrada tem entropia alta, não há dicionário a atacar, então o hash não precisa de sal. O estado no servidor permite revogar e detectar reuso.

### D2: `tokenVersion` e revogação imediata do access token

Todo access token carrega a claim `tv`. A cada requisição autenticada, um validador compara `tv` com `TOKEN_VERSION` do usuário no banco. Se forem diferentes (ou o usuário não existir), a resposta é 401 com a mensagem de token revogado.

**Trade-off:** o serviço faz **uma leitura por chave primária (projeção de uma coluna) em cada requisição autenticada**, em troca de **revogação imediata** de access tokens (logout-all, troca de senha, mudança de perfil). Consequências:

- latência extra pequena por requisição;
- se o banco estiver indisponível, as rotas protegidas falham com 500.

**Evolução possível:** cache com TTL curto (por exemplo 5 a 10 segundos). Isso reduziria a leitura, mas limitaria a janela de revogação a esse TTL. Não está implementado.

### D3: HTTP 429 com `Retry-After`

Bloqueio de conta por tentativas de login e limite de requisições por IP respondem 429 com o cabeçalho `Retry-After` (segundos inteiros, no mínimo 1) e o mesmo formato de erro (`ErroResponse`).

### D4: estado de proteção em memória do processo

Os contadores de falha de login (por conta) e o rate limit (por IP) ficam em memória (`ConcurrentHashMap`).

**Limitação de instância única:**

- com N réplicas, o limite efetivo passa a ser aproximadamente N vezes o configurado, pois cada instância conta sozinha;
- reiniciar o serviço zera bloqueios e janelas;
- o rate limit usa janela fixa, então uma rajada na virada de janela pode chegar a cerca de 2 vezes o limite sem bloqueio.

Perder esse estado só reduz a proteção temporariamente e não corrompe dados de negócio. **Antes de escalar horizontalmente**, a evolução prevista é mover os contadores para Redis (`INCR` + `EXPIRE`), mantendo as interfaces `ForcaBrutaService` e `RateLimitService`.

## Proteções adicionais

- **Força bruta por conta**: após `max-attempts` falhas dentro de `window`, a conta fica bloqueada por `duration` (429). O e-mail não aparece em claro em memória nem em log (usa hash).
- **Sem enumeração de usuário**: login com e-mail inexistente e senha errada têm a mesma resposta (401) e o mesmo custo de BCrypt (hash fictício).
- **Rate limit por IP** em `POST /v1/auth/login` e `POST /v1/auth/refresh`.
- **Política de senha**: 8 a 64 caracteres, no máximo 72 bytes em UTF-8, diferente do e-mail e fora da lista de senhas comuns.
- **Último ADMIN**: não é possível rebaixar o último usuário com perfil ADMIN (409).
- **Auditoria**: eventos de segurança (login, falhas, bloqueio, refresh, reuso, logout) são gravados em `EVENTOS_SEGURANCA` e logados sem dados pessoais sensíveis.
- **Senhas e tokens** nunca aparecem em log nem em `toString()`.

## Endpoints

Todos sob `/v1`. No perfil `dev` há o prefixo `/gestao-usuarios-api` e a porta 8081.

| Método | Rota | Acesso | Descrição |
|---|---|---|---|
| POST | `/v1/usuarios` | público | Cadastra usuário (perfil sempre `USER`) |
| POST | `/v1/auth/login` | público | Autentica e emite o par de tokens |
| POST | `/v1/auth/refresh` | público | Rotaciona o refresh token |
| POST | `/v1/auth/logout` | público | Encerra a sessão do refresh token informado |
| POST | `/v1/auth/logout-all` | autenticado | Encerra todas as sessões do usuário |
| GET | `/v1/me` | autenticado | Dados do usuário logado |
| PUT | `/v1/me` | autenticado | Atualiza o nome |
| PUT | `/v1/me/senha` | autenticado | Troca a senha |
| GET | `/v1/usuarios` | ADMIN | Lista paginada |
| GET | `/v1/usuarios/{id}` | ADMIN | Consulta por id |
| PUT | `/v1/usuarios/{id}/perfil` | ADMIN | Altera o perfil |
| DELETE | `/v1/usuarios/{id}` | ADMIN | Exclui o usuário |

Documentação OpenAPI: `/swagger-ui.html` (JSON em `/swagger-ui/api-docs`), públicos.

## Configuração

### Variáveis de ambiente

Nenhum valor real deve ser versionado. Defina as variáveis no ambiente de execução.

| Variável | Obrigatória | Descrição |
|---|---|---|
| `JWT_SECRET` | em produção | Segredo HMAC do JWT. Com o perfil `prod`, a aplicação **não sobe** se o segredo tiver menos de 32 bytes ou usar o prefixo padrão de desenvolvimento (`dev-only-secret-`). Sem a variável, vale um default fraco apenas para dev/test |
| `ADMIN_EMAIL`, `ADMIN_SENHA`, `ADMIN_NOME` | opcionais, as três juntas | Criam o admin inicial no boot, somente se as três estiverem preenchidas (sem default). Se o e-mail já existir, nada é alterado. A senha segue a política de senha; se for inválida, o boot falha |
| `PROFILE` | não | Perfil Spring ativo. Default `prod`. Para desenvolvimento local use `PROFILE=dev` |
| `DATASOURCE_IP`, `DATASOURCE_PORT`, `DATASOURCE_BANCO`, `DATASOURCE_USER`, `DATASOURCE_PASSWORD` | sim | Conexão PostgreSQL |

### Propriedades (`application.yml`)

| Propriedade | Default | Faixa válida |
|---|---|---|
| `dispensaai.security.jwt.secret` | `${JWT_SECRET:<default de dev>}` | não vazio; em `prod`, >= 32 bytes e sem prefixo de dev |
| `dispensaai.security.jwt.access-expiration` | `900` (segundos) | 600 a 900 |
| `dispensaai.security.refresh.expiration` | `7d` | 7d a 30d |
| `dispensaai.security.lockout.max-attempts` | `5` | 1 a 100 |
| `dispensaai.security.lockout.window` | `15m` | 1 min a 24 h |
| `dispensaai.security.lockout.duration` | `15m` | 1 min a 24 h |
| `dispensaai.security.ratelimit.max-requests` | `20` | 1 a 10000 |
| `dispensaai.security.ratelimit.window` | `1m` | 1 s a 1 h |
| `dispensaai.security.senha.senhas-comuns` | lista embutida em `PasswordPolicyProperties` | lista de senhas proibidas; se ausente ou vazia, usa a lista padrão |
| `dispensaai.admin-inicial.email` / `senha` / `nome` | vazio | vêm de `ADMIN_EMAIL`, `ADMIN_SENHA`, `ADMIN_NOME` |
| `dispensaai.eventos.usuario-criado.enabled` | `false` | publicação do evento de usuário criado |

Valores fora da faixa impedem o boot, com erro citando a propriedade.

### Atrás de proxy ou load balancer

O IP usado no rate limit e na auditoria vem de `getRemoteAddr()`. Por padrão o cabeçalho `X-Forwarded-For` **não** é confiado. Atrás de um proxy, sem configuração, todos os clientes pareceriam ter o IP do proxy e compartilhariam o mesmo limite. Configure o Spring Boot para confiar apenas no proxy conhecido:

```properties
server.forward-headers-strategy=native
server.tomcat.remoteip.internal-proxies=<regex ou lista dos IPs dos seus proxies>
```

Não confie em `X-Forwarded-For` vindo de origens não controladas, pois o cliente poderia forjar o IP e escapar do rate limit.

## Banco de dados

O Flyway aplica as migrações em `src/main/resources/db/migration`: `V1` cria `USUARIOS` e `V2` adiciona `TOKEN_VERSION`, `ULTIMO_LOGIN_EM` e as tabelas `REFRESH_TOKENS` e `EVENTOS_SEGURANCA`. O Hibernate roda com `ddl-auto: validate`.

## Como rodar e testar

O `java` do PATH pode ser o Java 8. Use o JDK 25 via `JAVA_HOME` e rode o Maven a partir de `gestaousuarios/`. Exemplo (Git Bash; ajuste os caminhos à sua máquina e remova `-o` se precisar baixar dependências):

```bash
export JAVA_HOME=<caminho-do-jdk-25>
MVN=<caminho-do-mvn>   # ou ./mvnw, se o wrapper puder baixar o Maven

# Padrão: testes rápidos, sem banco (exclui os *IT e o PasswordEncoderPropertyTest)
$MVN -o test

# Somente os ITs (exige PostgreSQL: IT_DB_URL/IT_DB_USER/IT_DB_PASSWORD ou Docker)
$MVN -o test -Pit

# Tudo: rápidos + ITs + teste lento de BCrypt (cerca de 4 min)
$MVN -o test -Pfull
```

O `mvn test` padrão **não** roda os ITs. Em CI, rode também `-Pit` e falhe o build se houver testes pulados, porque sem banco os ITs são pulados em silêncio.

Observações:

- **ITs sem Docker (banco externo):** defina `IT_DB_URL`, `IT_DB_USER` e `IT_DB_PASSWORD` apontando para um banco **dedicado** aos testes (nunca o de desenvolvimento). Ele precisa estar limpo antes da suíte; recrie-o, por exemplo, com `DROP DATABASE IF EXISTS gestaousuarios_it WITH (FORCE); CREATE DATABASE gestaousuarios_it OWNER <usuario>;`.
- Sem `IT_DB_URL`, os testes de integração (`*IT`) usam Testcontainers com PostgreSQL e **exigem o Docker em execução**. Sem o daemon eles são pulados em silêncio, então um `-Pit` verde sem Docker nem `IT_DB_URL` não cobre os ITs.
- Testes novos que usam BCrypt devem usar custo 4 (`BCryptPasswordEncoder(4)`) ou um fake, nunca o custo 12.
- Testes de propriedade usam jqwik (fixado em 1.9.3).

Para rodar localmente em desenvolvimento, tenha um PostgreSQL acessível, exporte `PROFILE=dev` e `DATASOURCE_*` e use `./mvnw spring-boot:run`. Para criar o admin inicial, exporte `ADMIN_EMAIL`, `ADMIN_SENHA` e `ADMIN_NOME` no shell antes de iniciar, sem gravar valores em arquivos versionados.
