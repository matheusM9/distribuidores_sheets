# DISTRIBUIDORES APP - STREAMLIT (GOOGLE SHEETS)
# Versão sem mapa e sem latitude/longitude (apenas cadastro, listar, editar, excluir + META MENSAL)
# Base: https://docs.google.com/spreadsheets/d/1hxPKagOnMhBYI44G3vQHY_wQGv6iYTxHMd_0VLw2r-k (aba "Página1")

import os
import json
import re
import requests
import pandas as pd
import bcrypt
import io

import streamlit as st
from streamlit_cookies_manager import EncryptedCookieManager

# Google Sheets
import gspread
from google.oauth2.service_account import Credentials
from google.auth.exceptions import DefaultCredentialsError, RefreshError

st.set_page_config(page_title="Distribuidores", layout="wide")

# -----------------------------
# CONFIGURAÇÃO GOOGLE SHEETS
# -----------------------------
SHEET_ID = "1hxPKagOnMhBYI44G3vQHY_wQGv6iYTxHMd_0VLw2r-k"
SHEET_NAME = "Página1"
SHEET_CLASS_NAME = "Classificacoes"
COLUNAS = ["Distribuidor", "Contato", "Email", "Estado", "Cidade", "Meta Mensal"]

# -----------------------------
# Inicializar Google Sheets client
# -----------------------------
SCOPE = [
    "https://spreadsheets.google.com/feeds",
    "https://www.googleapis.com/auth/drive",
]
GC = None
WORKSHEET = None
WORKSHEET_CLASS = None

def init_gsheets():
    global GC, WORKSHEET, WORKSHEET_CLASS
    if "gcp_service_account" not in st.secrets:
        st.error("❌ Google Service Account não configurada nos Secrets do Streamlit Cloud.")
        st.stop()
    try:
        creds_dict = st.secrets["gcp_service_account"]
        creds = Credentials.from_service_account_info(creds_dict, scopes=SCOPE)
        GC = gspread.authorize(creds)
        sh = GC.open_by_key(SHEET_ID)
        # main worksheet
        try:
            WORKSHEET = sh.worksheet(SHEET_NAME)
        except gspread.WorksheetNotFound:
            WORKSHEET = sh.add_worksheet(title=SHEET_NAME, rows="2000", cols=str(len(COLUNAS)))
            WORKSHEET.update([COLUNAS])
        # classification worksheet
        try:
            WORKSHEET_CLASS = sh.worksheet(SHEET_CLASS_NAME)
        except gspread.WorksheetNotFound:
            WORKSHEET_CLASS = sh.add_worksheet(title=SHEET_CLASS_NAME, rows="2000", cols="3")
            WORKSHEET_CLASS.update([["Cidade","Estado","Classificacao"]])
    except (DefaultCredentialsError, RefreshError, Exception) as e:
        st.error("Erro ao autenticar Google Sheets. Verifique o Secret da Service Account.\n" + str(e))
        st.stop()

init_gsheets()

# -----------------------------
# FUNÇÕES DE DADOS (Sheets)
# -----------------------------
@st.cache_data(ttl=300)
def carregar_dados():
    try:
        records = WORKSHEET.get_all_records()
    except Exception as e:
        st.error("Erro ao ler planilha: " + str(e))
        return pd.DataFrame(columns=COLUNAS)
    if not records:
        df = pd.DataFrame(columns=COLUNAS)
        try:
            WORKSHEET.clear()
            WORKSHEET.update([COLUNAS])
        except:
            pass
        return df
    df = pd.DataFrame(records)
    for col in COLUNAS:
        if col not in df.columns:
            df[col] = ""
    return df[COLUNAS]

def salvar_dados(df):
    try:
        df2 = df.copy()
        df2 = df2[COLUNAS].fillna("")
        # write back (overwrite)
        WORKSHEET.clear()
        WORKSHEET.update([df2.columns.values.tolist()] + df2.values.tolist())
        try:
            st.cache_data.clear()
        except:
            pass
    except Exception as e:
        st.error("Erro ao salvar dados: " + str(e))

# -----------------------------
# CLASSIFICAÇÕES (sheet separada)
# -----------------------------
@st.cache_data(ttl=60)
def carregar_classificacoes():
    try:
        recs = WORKSHEET_CLASS.get_all_records()
    except Exception as e:
        # se erro, retorna DF vazio com colunas
        return pd.DataFrame(columns=["Cidade","Estado","Classificacao"])
    dfc = pd.DataFrame(recs)
    # garantir colunas
    for c in ["Cidade","Estado","Classificacao"]:
        if c not in dfc.columns:
            dfc[c] = ""
    return dfc

def salvar_classificacao_entry(cidade, estado, classificacao):
    # upsert na folha Classificacoes
    dfc = carregar_classificacoes()
    # procurar correspondência exata (cidade+estado)
    mask = (dfc["Cidade"].str.lower().str.strip() == cidade.lower().strip()) & (dfc["Estado"].str.upper().str_strip() == estado.upper().strip()) if ("str_strip" in dir(str)) else (dfc["Cidade"].str.lower().str.strip() == cidade.lower().strip()) & (dfc["Estado"].str.upper().str.strip() == estado.upper().strip())
    # Python versions differ on string functions; use safe approach:
    mask = (dfc["Cidade"].astype(str).str.lower().str.strip() == cidade.lower().strip()) & (dfc["Estado"].astype(str).str.upper().str.strip() == estado.upper().strip())
    if mask.any():
        dfc.loc[mask, "Classificacao"] = classificacao
    else:
        dfc = pd.concat([dfc, pd.DataFrame([[cidade, estado, classificacao]], columns=["Cidade","Estado","Classificacao"])], ignore_index=True)
    # write back
    WORKSHEET_CLASS.clear()
    WORKSHEET_CLASS.update([dfc.columns.values.tolist()] + dfc.values.tolist())
    try:
        st.cache_data.clear()
    except:
        pass

def get_classificacao(cidade, estado):
    # retorna classificacao para cidade+estado. se não existir -> 'Caráter Exclusivo'
    dfc = carregar_classificacoes()
    if dfc.empty:
        return "Caráter Exclusivo"
    cidade = str(cidade).strip()
    estado = str(estado).strip().upper()
    match = dfc[(dfc["Cidade"].astype(str).str.lower().str.strip() == cidade.lower()) & (dfc["Estado"].astype(str).str.upper().str.strip() == estado.upper())]
    if not match.empty:
        val = str(match.iloc[0]["Classificacao"]).strip()
        return val if val else "Caráter Exclusivo"
    return "Caráter Exclusivo"

# -----------------------------
# COOKIES (LOGIN PERSISTENTE)
# -----------------------------
cookies = EncryptedCookieManager(
    prefix="distribuidores_login",
    password="chave_secreta_segura_123"
)
if not cookies.ready():
    st.stop()

# -----------------------------
# CAPITAIS BRASILEIRAS
# -----------------------------
CAPITAIS_BRASILEIRAS = [
    "Rio Branco-AC", "Maceió-AL", "Macapá-AP", "Manaus-AM", "Salvador-BA", "Fortaleza-CE",
    "Brasília-DF", "Vitória-ES", "Goiânia-GO", "São Luís-MA", "Cuiabá-MT", "Campo Grande-MS",
    "Belo Horizonte-MG", "Belém-PA", "João Pessoa-PB", "Curitiba-PR", "Recife-PE", "Teresina-PI",
    "Rio de Janeiro-RJ", "Natal-RN", "Porto Alegre-RS", "Boa Vista-RR", "Florianópolis-SC",
    "São Paulo-SP", "Aracaju-SE", "Palmas-TO"
]

def cidade_eh_capital(cidade, uf):
    return f"{cidade}-{uf}" in CAPITAIS_BRASILEIRAS

# -----------------------------
# FUNÇÕES AUXILIARES (IBGE)
# -----------------------------
@st.cache_data
def carregar_estados():
    url = "https://servicodados.ibge.gov.br/api/v1/localidades/estados"
    resp = requests.get(url)
    return sorted(resp.json(), key=lambda e: e["nome"])

@st.cache_data
def carregar_cidades_por_uf(uf):
    url = f"https://servicodados.ibge.gov.br/api/v1/localidades/estados/{uf}/municipios"
    resp = requests.get(url)
    return sorted(resp.json(), key=lambda c: c["nome"])

@st.cache_data(ttl=24*60*60)
def carregar_todas_cidades():
    """Retorna lista com 'Cidade - UF' para todas as cidades do Brasil (cache de 24h)."""
    estados = carregar_estados()
    todas = []
    for e in estados:
        sigla = e["sigla"]
        try:
            municipios = carregar_cidades_por_uf(sigla)
            for m in municipios:
                todas.append(f"{m['nome']} - {sigla}")
        except:
            # se alguma falha na API, ignora
            pass
    return sorted(todas)

# -----------------------------
# LOGIN
# -----------------------------
USUARIOS_FILE = "usuarios.json"

def init_usuarios():
    try:
        with open(USUARIOS_FILE, "r") as f:
            usuarios = json.load(f)
            if not isinstance(usuarios, dict):
                raise ValueError("Formato inválido")
    except:
        senha_hash = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
        usuarios = {"admin": {"senha": senha_hash, "nivel": "editor"}}
        with open(USUARIOS_FILE, "w") as f:
            json.dump(usuarios, f, indent=4)
    return usuarios

usuarios = init_usuarios()
usuario_cookie = cookies.get("usuario", "")
nivel_cookie = cookies.get("nivel", "")
logado = usuario_cookie != "" and nivel_cookie != ""

if not logado:
    st.title("🔐 Login")
    usuario = st.text_input("Usuário")
    senha = st.text_input("Senha", type="password")
    if st.button("Entrar"):
        if usuario in usuarios and bcrypt.checkpw(senha.encode(), usuarios[usuario]["senha"].encode()):
            cookies["usuario"] = usuario
            cookies["nivel"] = usuarios[usuario]["nivel"]
            cookies.save()
            st.rerun()
        else:
            st.error("Usuário ou senha incorretos!")
    st.stop()

st.sidebar.write(f"👤 {usuario_cookie} ({nivel_cookie})")
if st.sidebar.button("Sair"):
    cookies["usuario"] = ""
    cookies["nivel"] = ""
    cookies.save()
    st.rerun()

# -----------------------------
# CARREGAR TABELA
# -----------------------------
if "df" not in st.session_state:
    st.session_state.df = carregar_dados()

# NOVO MENU (inclui Classificação)
menu = ["Cadastro", "Lista / Editar / Excluir", "🔎 Buscar", "Classificação de Cidade"]
choice = st.sidebar.radio("Menu", menu)

# -----------------------------
# VALIDAÇÕES
# -----------------------------
def validar_telefone(tel):
    return re.match(r'^\(\d{2}\) \d{4,5}-\d{4}$', tel)

def validar_email(email):
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)

# helpers
def to_float_safe(x):
    try:
        return float(str(x).replace(",", "."))
    except:
        return 0.0

# =============================
# CADASTRO
# =============================
if choice == "Cadastro" and nivel_cookie == "editor":

    st.subheader("Cadastrar Novo Distribuidor")

    col1, col2 = st.columns(2)
    with col1:
        estados = carregar_estados()
        siglas = [e["sigla"] for e in estados]
        estado_sel = st.selectbox("Estado", siglas)
        cidades = [c["nome"] for c in carregar_cidades_por_uf(estado_sel)]
        cidades_sel = st.multiselect("Cidades", cidades)

    with col2:
        nome = st.text_input("Nome do Distribuidor")
        contato = st.text_input("Contato (formato: (XX) XXXXX-XXXX)")
        email = st.text_input("Email")
        meta = st.number_input("Meta Mensal (R$)", min_value=0.0, step=100.0, format="%.2f")

    if st.button("Adicionar Distribuidor"):

        if not nome or not contato or not email or not estado_sel or not cidades_sel:
            st.error("Preencha todos os campos!")
        elif not validar_telefone(contato):
            st.error("Telefone inválido!")
        elif not validar_email(email):
            st.error("Email inválido!")
        elif nome in st.session_state.df["Distribuidor"].tolist():
            st.error("Distribuidor já existe!")
        else:
            cidades_ocupadas = []
            # verificar por cada cidade a classificação
            for c in cidades_sel:
                classificacao = get_classificacao(c, estado_sel)
                # se classificação permite múltiplos, não bloquear
                if classificacao in ["Área Aberta", "Área Aberta Cliente Fechado"]:
                    continue
                # senão respeitar regra antiga (não permitir se cidade já tem distribuidor e não for capital)
                if c in st.session_state.df["Cidade"].tolist() and not cidade_eh_capital(c, estado_sel):
                    dist_exist = st.session_state.df.loc[st.session_state.df["Cidade"] == c, "Distribuidor"].iloc[0]
                    cidades_ocupadas.append(f"{c} (pertence a {dist_exist})")

            if cidades_ocupadas:
                st.error("\n".join(cidades_ocupadas))
            else:
                novos = []
                for c in cidades_sel:
                    novos.append([nome, contato, email, estado_sel, c, float(meta)])

                novo_df = pd.DataFrame(novos, columns=COLUNAS)
                st.session_state.df = pd.concat([st.session_state.df, novo_df], ignore_index=True)

                salvar_dados(st.session_state.df)
                st.session_state.df = carregar_dados()

                st.success(f"Distribuidor '{nome}' cadastrado com sucesso!")

# =============================
# LISTA / EDITAR / EXCLUIR
# =============================
elif choice == "Lista / Editar / Excluir":

    st.subheader("Distribuidores Cadastrados")

    st.dataframe(
        st.session_state.df[["Distribuidor", "Contato", "Email", "Estado", "Cidade", "Meta Mensal"]],
        use_container_width=True
    )

    # EDITAR
    if nivel_cookie == "editor":
        with st.expander("✏️ Editar"):
            if not st.session_state.df.empty:
                dist_edit = st.selectbox("Selecione", st.session_state.df["Distribuidor"].unique())
                dados = st.session_state.df[st.session_state.df["Distribuidor"] == dist_edit]

                nome_edit = st.text_input("Nome", dados.iloc[0]["Distribuidor"])
                contato_edit = st.text_input("Contato", dados.iloc[0]["Contato"])
                email_edit = st.text_input("Email", dados.iloc[0]["Email"])

                # -------------------------------
                # CORREÇÃO DA META — sempre mostra 0 se estiver vazia
                # -------------------------------
                try:
                    meta_valor = float(str(dados.iloc[0]["Meta Mensal"]).replace(",", "."))
                except:
                    meta_valor = 0.0

                meta_edit = st.number_input(
                    "Meta Mensal (R$)",
                    min_value=0.0,
                    step=100.0,
                    format="%.2f",
                    value=meta_valor
                )
                # -------------------------------

                estados_uniq = sorted(dados["Estado"].unique())
                estado_edit = st.selectbox("Estado", estados_uniq, index=0)

                cidades_disponiveis = [c["nome"] for c in carregar_cidades_por_uf(estado_edit)]
                cidades_novas = st.multiselect(
                    "Cidades",
                    cidades_disponiveis,
                    default=dados["Cidade"].tolist()
                )

                if st.button("Salvar"):

                    if not validar_telefone(contato_edit):
                        st.error("Telefone inválido!")
                    elif not validar_email(email_edit):
                        st.error("Email inválido!")
                    else:
                        outras = st.session_state.df[st.session_state.df["Distribuidor"] != dist_edit]
                        ocupadas = []

                        for cidade in cidades_novas:
                            classificacao = get_classificacao(cidade, estado_edit)
                            # se classificação permite múltiplos, ignora ocupação
                            if classificacao in ["Área Aberta", "Área Aberta Cliente Fechado"]:
                                continue
                            if cidade in outras["Cidade"].tolist() and not cidade_eh_capital(cidade, estado_edit):
                                de = outras.loc[outras["Cidade"] == cidade, "Distribuidor"].iloc[0]
                                ocupadas.append(f"{cidade} pertence a {de}")

                        if ocupadas:
                            st.error("\n".join(ocupadas))
                        else:
                            # remover linhas antigas do distribuidor sendo editado
                            st.session_state.df = st.session_state.df[
                                st.session_state.df["Distribuidor"] != dist_edit
                            ]

                            novos = []
                            for cidade in cidades_novas:
                                novos.append([
                                    nome_edit,
                                    contato_edit,
                                    email_edit,
                                    estado_edit,
                                    cidade,
                                    float(meta_edit)
                                ])

                            novo_df = pd.DataFrame(novos, columns=COLUNAS)

                            st.session_state.df = pd.concat([st.session_state.df, novo_df], ignore_index=True)
                            salvar_dados(st.session_state.df)
                            st.session_state.df = carregar_dados()

                            st.success("Alterações salvas!")

        # EXCLUIR
        with st.expander("🗑️ Excluir"):
            if not st.session_state.df.empty:
                dist_del = st.selectbox("Excluir distribuidor", st.session_state.df["Distribuidor"].unique())
                if st.button("Excluir"):
                    st.session_state.df = st.session_state.df[
                        st.session_state.df["Distribuidor"] != dist_del
                    ]
                    salvar_dados(st.session_state.df)
                    st.session_state.df = carregar_dados()
                    st.success(f"Distribuidor '{dist_del}' removido!")

# =============================
# NOVA ABA ➜ BUSCAR (OPÇÃO C: cidade + distribuidor)
# =============================
elif choice == "🔎 Buscar":

    st.title("🔎 Buscar Distribuidor ou Cidade")

    df = st.session_state.df.copy()

    st.markdown("Escolha se deseja buscar por **Cidade** (todas as cidades do Brasil) ou por **Distribuidor** cadastrado.")

    coluna_busca = st.selectbox("Buscar por:", ["Cidade", "Distribuidor"])

    # ----- BUSCAR POR CIDADE (todas cidades do Brasil) -----
    if coluna_busca == "Cidade":
        todas_cidades = carregar_todas_cidades()  # formato: 'Cidade - UF'

        # campo para digitar parte do nome e filtrar a lista grande
        filtro_texto = st.text_input("Digite parte do nome da cidade para filtrar a lista (opcional):", "")
        if filtro_texto:
            sugestoes = [c for c in todas_cidades if filtro_texto.lower() in c.lower()]
            if not sugestoes:
                st.info("Nenhuma cidade encontrada com esse filtro.")
            cidade_sel = st.selectbox("Selecione a cidade (filtrada):", sugestoes)
        else:
            cidade_sel = st.selectbox("Selecione a cidade (todas as cidades do Brasil):", todas_cidades)

        if st.button("Verificar cidade"):
            try:
                nome_cidade, uf = [s.strip() for s in cidade_sel.rsplit(" - ", 1)]
            except:
                nome_cidade = cidade_sel
                uf = ""

            # usar contains para permitir correspondência parcial por segurança
            encontrados = df[
                (df["Cidade"].str.lower().str.strip() == nome_cidade.lower().strip()) &
                (df["Estado"].str.upper().str.strip() == uf.upper().strip())
            ]

            # fallback: se busca exata não encontrar, tentar contains (partial)
            if encontrados.empty:
                encontrados = df[
                    (df["Cidade"].str.lower().str.contains(nome_cidade.lower().strip(), na=False)) &
                    (df["Estado"].str.upper().str.strip() == uf.upper().strip())
                ]

            if encontrados.empty:
                st.error("❌ Não existe distribuidor para esta cidade.")
            else:
                encontrados["Meta Mensal Num"] = encontrados["Meta Mensal"].apply(to_float_safe)
                soma_meta = encontrados["Meta Mensal Num"].sum()

                st.success(f"✅ {len(encontrados)} registro(s) encontrado(s) para {nome_cidade} - {uf}.")
                st.metric("Meta Mensal total (R$)", f"R$ {soma_meta:,.2f}")
                st.dataframe(encontrados[["Distribuidor", "Contato", "Email", "Estado", "Cidade", "Meta Mensal"]], use_container_width=True)

                # CSV export
                csv_buffer = io.StringIO()
                encontrados.to_csv(csv_buffer, index=False)
                csv_bytes = csv_buffer.getvalue().encode("utf-8")
                st.download_button("📥 Exportar resultados (CSV)", data=csv_bytes, file_name=f"busca_{nome_cidade}_{uf}.csv", mime="text/csv")

    # ----- BUSCAR POR DISTRIBUIDOR -----
    else:
        lista_dists = sorted(df["Distribuidor"].dropna().unique())
        if not lista_dists:
            st.info("Nenhum distribuidor cadastrado ainda.")
        else:
            # permitir busca por parte do nome
            filtro_dist = st.text_input("Digite parte do nome do distribuidor para filtrar (opcional):", "")
            if filtro_dist:
                sugestoes_dist = [d for d in lista_dists if filtro_dist.lower() in d.lower()]
                if not sugestoes_dist:
                    st.info("Nenhum distribuidor encontrado com esse filtro.")
                dist_sel = st.selectbox("Selecione o distribuidor (filtrado):", sugestoes_dist)
            else:
                dist_sel = st.selectbox("Selecione o distribuidor:", lista_dists)

            if dist_sel:
                dados = df[df["Distribuidor"].str.lower().str.contains(dist_sel.lower(), na=False)]

                if dados.empty:
                    st.error("Nenhum dado encontrado para este distribuidor.")
                else:
                    dados["Meta Mensal Num"] = dados["Meta Mensal"].apply(to_float_safe)
                    soma_meta = dados["Meta Mensal Num"].sum()

                    st.subheader(f"Cidades atendidas por {dist_sel}:")
                    st.metric("Meta Mensal total (R$)", f"R$ {soma_meta:,.2f}")
                    st.dataframe(dados[["Distribuidor", "Contato", "Email", "Estado", "Cidade", "Meta Mensal"]], use_container_width=True)

                    # CSV export
                    csv_buffer = io.StringIO()
                    dados.to_csv(csv_buffer, index=False)
                    csv_bytes = csv_buffer.getvalue().encode("utf-8")
                    st.download_button("📥 Exportar resultados (CSV)", data=csv_bytes, file_name=f"busca_{dist_sel}.csv", mime="text/csv")

# =============================
# NOVA ABA ➜ CLASSIFICAÇÃO DE CIDADES
# =============================
elif choice == "Classificação de Cidade":

    st.title("🏷️ Classificação de Cidades")

    # carregar classificações e cidades
    df = st.session_state.df.copy()
    dfc = carregar_classificacoes()

    todas_cidades = carregar_todas_cidades()  # formato 'Cidade - UF'

    st.markdown("Escolha uma cidade (ou filtre pelo nome) e altere sua classificação.\
                 \n\nClassificações possíveis:\n\n- Área Aberta\n- Área Aberta Cliente Fechado\n- Liberado Primeira Venda\n- Caráter Exclusivo (padrão)")

    filtro_c = st.text_input("Filtrar cidades (parte do nome):", "")
    if filtro_c:
        sugest = [c for c in todas_cidades if filtro_c.lower() in c.lower()]
    else:
        sugest = todas_cidades

    cidade_sel = st.selectbox("Cidade:", sugest)

    if cidade_sel:
        try:
            nome_cidade, uf = [s.strip() for s in cidade_sel.rsplit(" - ", 1)]
        except:
            nome_cidade = cidade_sel
            uf = ""

        # identificar classificação atual
        atual = get_classificacao(nome_cidade, uf)

        opcoes_class = ["Área Aberta", "Área Aberta Cliente Fechado", "Liberado Primeira Venda", "Caráter Exclusivo"]
        nova_class = st.selectbox("Classificação:", opcoes_class, index=opcoes_class.index(atual) if atual in opcoes_class else opcoes_class.index("Caráter Exclusivo"))

        st.write(f"Classificação atual: **{atual}**")

        if st.button("Salvar Classificação"):
            salvar_classificacao_entry(nome_cidade, uf, nova_class)
            st.success("Classificação salva com sucesso!")
            # recarregar cache
            st.experimental_rerun()

    # Mostrar tabela de classificações existente (opcional)
    if not dfc.empty:
        st.subheader("Classificações registradas")
        st.dataframe(dfc, use_container_width=True)

# FIM DO ARQUIVO
