# safe-npm

[English](README.md) | **Português (Brasil)**

**Veja o pacote antes que ele execute.** O safe-npm é um scanner local de segurança estática para pacotes npm, escrito em Rust.

> A v0.5 adiciona evidência contextual, score mais resistente a falsos positivos e validação opcional com OpenAI sobre o scanner estático local. O safe-npm não executa o código do pacote.

## v0.5: análise por contexto + validação opcional com IA

A v0.5 foi criada para atacar os falsos positivos encontrados durante a calibração com pacotes reais.

- **Score deduplicado por regra:** repetir a mesma regra centenas ou milhares de vezes não multiplica mais o score do pacote.
- **Evidência contextual:** cada finding mantém um pequeno trecho do código em torno do comportamento encontrado.
- **Regras estáticas mais específicas:** uma URL isolada não é mais suficiente para indicar acesso à rede e a execução de processos prioriza APIs concretas.
- **Validação opcional com OpenAI:** use `--ai` com `OPENAI_API_KEY` para revisar findings HIGH/CRITICAL considerando o contexto do código.
- **IA não é obrigatória:** sem `--ai`, nenhum trecho de código é enviado para a OpenAI e o safe-npm continua local-first.
- Findings classificados como `false_positive` pela IA com confiança >= 0,80 são retirados antes do recálculo do risco.
- O modelo padrão é `gpt-5.6-luna`, podendo ser alterado com `--ai-model`.

```bash
export OPENAI_API_KEY="sua-chave"
safe-npm --ai scan lodash
safe-npm --ai tree express
safe-npm --ai --ai-model gpt-5.6-luna tree axios
```

### Privacidade e custo

Quando a IA é habilitada, o safe-npm envia para a Responses API da OpenAI o nome da regra, o caminho do arquivo e um pequeno trecho do código referente aos findings HIGH/CRITICAL. O pacote completo não é enviado por padrão. O uso de `--ai` requer acesso à internet, pode gerar custos de API e deve respeitar as políticas de código-fonte e dados da sua organização.

## Destaques da v0.4

- **Correlação comportamental:** eleva combinações de credenciais/ambiente + rede e rede + execução para CRITICAL.
- **Política do projeto:** o arquivo opcional `.safe-npm.toml` controla `block_at`, regras negadas, allowlist exata de pacotes e limites de varredura.
- **SARIF 2.1.0:** use `safe-npm tree express --sarif` para GitHub Code Scanning e outros consumidores de SARIF.
- A política é aplicada pelos comandos `scan` e `install`; a análise da árvore respeita os limites configurados.
- Corrige as falhas de CI com strict-clippy presentes na v0.3.

## Inteligência da v0.3

- **Heurística de typosquatting:** sinaliza nomes com uma edição de distância de um conjunto selecionado de pacotes npm populares.
- **Sinais de confiança do Registry:** versões depreciadas, ausência de mantenedores e histórico de versões extremamente curto.
- **Heurística de densidade de ofuscação:** detecta linhas anormalmente longas/minificadas e uso intenso de escapes hex/unicode.
- Os sinais do Registry são pontuados junto aos findings do código-fonte em toda a árvore de dependências.
- Todas as proteções da árvore de dependências da v0.2 permanecem: resolução SemVer, proteção contra ciclos/duplicidades, varredura limitada e política de instalação segura.

## Base da v0.2

- Análise recursiva da árvore de dependências com proteção contra ciclos e duplicidades.
- Resolução de intervalos SemVer usando o npm Registry.
- `--max-depth` configurável (padrão 8) e `--max-packages` (padrão 500).
- Risco agregado da árvore: o maior risco encontrado entre os pacotes passa a ser o risco utilizado pela política de instalação.
- Dependências provenientes de git/file/http não suportadas são reportadas em vez de serem silenciosamente consideradas confiáveis.
- O modo `scan` para um único pacote continua disponível.
- O comando `install` analisa a árvore de dependências antes de permitir que o npm seja executado.
- Scripts de lifecycle permanecem desabilitados por padrão através de `--ignore-scripts`.
- Relatório JSON da árvore para CI/CD.
- Landing page estática em `docs/`, pronta para GitHub Pages.

## Instalação

```bash
cargo install --git https://github.com/mdnbras/safe-npm
```

## Uso

Analisar um único tarball:

```bash
safe-npm scan lodash
safe-npm scan lodash --json
```

Analisar toda a árvore de dependências de produção:

```bash
safe-npm tree express
safe-npm tree express --max-depth 10 --max-packages 1000
safe-npm tree express --json
```

Analisar a árvore e instalar somente se a política permitir:

```bash
safe-npm install express
```

Um risco HIGH ou CRITICAL em qualquer ponto da árvore analisada bloqueia a instalação. Sobrescritas precisam ser explícitas:

```bash
safe-npm install package --allow-risk
safe-npm install package --allow-scripts
```

## Calibração com pacotes reais

Para exercitar o scanner contra código do mundo real, a v0.4 foi executada contra cinco pacotes npm amplamente utilizados: `lodash`, `express`, `react`, `axios` e `typescript`. O teste foi executado em 01/10/2026 utilizando as versões resolvidas pelo npm Registry naquele momento.

Esses são exemplos de pacotes com uso massivo, e não um ranking permanente ou oficial de "top 5". A quantidade de downloads e as versões dos pacotes mudam ao longo do tempo.

| Pacote | Versão | Pacotes analisados | Arquivos analisados | Findings | Risco da árvore |
|---|---:|---:|---:|---:|---|
| lodash | 4.18.1 | 1 | 1.049 | 82 | CRITICAL |
| express | 5.2.1 | 68 | 341 | 110 | CRITICAL |
| react | 19.3.0 | 1 | 25 | 30 | CRITICAL |
| axios | 1.20.0 | 30 | 290 | 101 | CRITICAL |
| typescript | 7.0.2 | 21 | 2.387 | 2.261 | CRITICAL |

![Análise de pacotes com safe-npm](docs/assets/package-analysis-v04.svg)

### O que esses resultados significam

Essa calibração revelou uma limitação importante no conjunto atual de regras. Os cinco pacotes atingiram CRITICAL, sendo `network-access` responsável pela maior parte dos findings. Por exemplo, TypeScript produziu 2.170 findings de `network-access`, enquanto lodash produziu 70.

**Essa tabela não deve ser interpretada como uma afirmação de que esses pacotes contêm malware.** O nível de risco do safe-npm é um sinal heurístico para revisão. O teste mostra que a v0.4 ainda precisa de maior compreensão de contexto e precisão nas regras antes que o score possa ser tratado como uma classificação forte de segurança de um pacote.

É justamente por isso que esses exemplos permanecem no repositório: eles fornecem um baseline reproduzível para medir a redução de falsos positivos nas próximas versões.

Os relatórios JSON brutos são gerados pelo workflow `Package examples` do GitHub Actions e enviados como artifact `safe-npm-package-examples`.

Execute o mesmo teste localmente:

```bash
cargo build --release

for pkg in lodash express react axios typescript; do
  ./target/release/safe-npm tree "$pkg" --json > "$pkg.json"
done
```

## O que é detectado?

O conjunto atual de regras procura scripts de lifecycle, execução de processos/shell, execução dinâmica de código, acesso a credenciais/tokens, acesso a variáveis de ambiente, código com capacidade de comunicação em rede e indicadores de payloads codificados/ofuscados.

| Severidade | Peso |
|---|---:|
| LOW | 3 |
| MEDIUM | 10 |
| HIGH | 25 |
| CRITICAL | 40 |

Score do pacote: LOW 0–19, MEDIUM 20–44, HIGH 45–74 e CRITICAL 75–100.

## Arquitetura

```text
pacote@intervalo
      |
      v
metadados do npm Registry
      |
      +---- resolver SemVer ----+
      |                         |
      v                         v
baixar .tgz raiz         intervalos das dependências
      |                         |
      v                         +---- fila recursiva
scanner estático                        |
      |                                 v
      +----------------------- analisar .tgz da dependência
                                        |
                                        v
                              deduplicar / evitar ciclos
                                        |
                                        v
                              agregar risco da árvore
                                        |
                           +------------+-------------+
                           |                          |
                       relatório             política de instalação
                                                      |
                                             npm --ignore-scripts
```

## Landing page

O código-fonte do site está em `docs/`. Um workflow do GitHub Pages está incluído em `.github/workflows/pages.yml`.

Quando o Pages está configurado para utilizar **GitHub Actions** como fonte, pushes que alterem `docs/` fazem o deploy do site automaticamente.

## Limites de segurança

O safe-npm v0.5 deliberadamente não executa os pacotes baixados. Arquivos individuais de código-fonte maiores que 2 MiB são ignorados. A varredura da árvore é limitada por profundidade e quantidade de pacotes. Dependências provenientes de Git, arquivos locais e HTTP direto são atualmente reportadas como não suportadas em vez de serem baixadas.

O scanner é heurístico: **um finding não é prova de malware, e um relatório limpo não é prova de segurança.** Use o safe-npm como uma camada de defesa em profundidade junto com npm audit, verificação de proveniência/assinatura, lockfiles, revisão de código e isolamento em runtime.

## Roadmap

- Análise JavaScript/TypeScript baseada em AST.
- Typosquatting e similaridade de nomes de pacotes.
- Verificação de assinatura/proveniência do Registry.
- Sinais relacionados à idade do pacote, mantenedores e anomalias de releases.
- Heurísticas de entropia/minificação.
- Políticas e allowlists configuráveis.
- SARIF / GitHub Code Scanning.
- Downloads/análises paralelos e cache de metadados.

## Política

Crie `.safe-npm.toml` na raiz do projeto ou informe `--policy caminho/para/policy.toml`:

```toml
block_at = "HIGH"
max_depth = 8
max_packages = 500
deny_rules = ["credential-access", "behavior-secret-exfiltration", "behavior-download-execute"]
allow_packages = []
```

Gerar SARIF:

```bash
safe-npm tree express --sarif > safe-npm.sarif
```

## Desenvolvimento

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

## Licença

MIT
