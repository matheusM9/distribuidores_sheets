# app.py
# -------------------------------------------------------------
# DISTRIBUIDORES APP - STREAMLIT (GOOGLE SHEETS) - VERSÃO OTIMIZADA
# Objetivo: mapa rápido (< 1 minuto), cache robusto, deploy pronto.
# -------------------------------------------------------------

import json
import re
import time
from typing import Optional, Tuple

import pandas as pd
import requests
import folium
import bcrypt

import streamlit as st
from streamlit_folium import st_folium
from streamlit_cookies_manager import EncryptedCookieManager

# Google Sheets
import gspread
from google.oauth2.service_account import Credentials
from google.auth.exceptions import DefaultCredentialsError, RefreshError

# Geocoding (used only on add/edit, not on every run)
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut, GeocoderUnavailable

# -----------------------------
# CONFIGURAÇÕES
# -----------------------------
st.set_page_config(page_title="Distribuidores", layout="wide")

# Google Sheets (use seu ID já conhecido)
SHEET_ID = "1hxPKagOnMhBYI44G3vQHY_wQGv6iYTxHMd_0VLw2r-k"
SHEET_NAME = "Página1"
COLUNAS = ["Distribuidor", "Contato", "Email", "Estado", "Cidade", "Latitude", "Longitude"]

# IBGE endpoints (compactos quando possível)
IBGE_ESTADOS_URL = "https://servicodados.ibge.gov.br/api/v1/localidades/estados"
IBGE_CIDADES_URL = "https://servicodados.ibge.gov.br/api/v1/localidades/estados/{uf}/municipios"
IBGE_MALHA_CIDADE = "https://servicodados.ibge.gov.br/api/v2/malhas/{id}?formato=application/vnd.geo+json&qualidade=intermediaria"
IBGE_MALHAS_ESTADOS = ("https://servicodados.ibge.gov.br/api/v2/malhas/"
                      "?formato=application/vnd.geo+json&qualidade=simplificada&incluir=estados")

# Segurança / cookies
COOKIE_PREFIX = "distribuidores_login"
COOKIE_PASSWORD = "chave_secreta_segura_123"  # troque para algo seguro em produção

# GEO LIMITS (Brasil)
LAT_MIN, LAT_MAX = -35.0, 6.0
LON_MIN, LON_MAX = -82.0, -30.0

# -----------------------------
# INICIALIZAÇÃO: Google Sheets client (robusto)
# -----------------------------
@st.cache_resource(show_spinner=False)
def init_gsheets_client():
    """Inicializa client gspread usando st.secrets['gcp_service_account'] (recomendado)"""
    try:
        # Prefer st.secrets - mais seguro para deploys como Streamlit/Render
        if "gcp_service_account" in st.secrets:
            creds_info = st.secrets["gcp_service_account"]
            creds = Credentials.from_service_account_info(creds_info, scopes=[
                "https://spreadsheets.google.com/feeds",
                "https://www.googleapis.com/auth/drive",
            ])
        else:
            # Fallback: procura arquivo credentials.json local (útil para desenvolvimento)
            creds = Credentials.from_service_account_file("credentials.json", scopes=[
                "https://spreadsheets.google.com/feeds",
                "https://www.googleapis.com/auth/drive",
            ])
        gc = gspread.authorize(creds)
        sh = gc.open_by_key(SHEET_ID)
        try:
            ws = sh.worksheet(SHEET_NAME)
        except gspread.WorksheetNotFound:
            ws = sh.add_worksheet(title=SHEET_NAME, rows="1000", cols=str(len(COLUNAS)))
            ws.update([COLUNAS])
        return ws
    except Exception as e:
        st.error("Erro ao autenticar Google Sheets. Verifique credenciais.\n" + str(e))
        st.stop()


WORKSHEET = init_gsheets_client()

# -----------------------------
# UTIL: sanitização lat/lon
# -----------------------------
def to_float_safe(x) -> Optional[float]:
    if x is None:
        return None
    if isinstance(x, (int, float)):
        return float(x)
    s = str(x).strip()
    if s == "":
        return None
    s = s.replace(",", ".").replace(" ", "")
    try:
        return float(s)
    except Exception:
        return None


def latlon_valid(lat, lon) -> bool:
    try:
        if lat is None or lon is None:
            return False
        return LAT_MIN <= float(lat) <= LAT_MAX and LON_MIN <= float(lon) <= LON_MAX
    except Exception:
        return False

# -----------------------------
# CACHE INTELIGENTE DE DADOS (Sheets)
# -----------------------------
if "cache_key" not in st.session_state:
    st.session_state.cache_key = 0  # incrementa apenas quando salvo

@st.cache_data(show_spinner=False)
def carregar_dados(cache_key: int) -> pd.DataFrame:
    """
    Busca dados do Google Sheets e sanitiza. Cache depende de cache_key (para invalidação controlada).
    """
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
        except Exception:
            pass
        return df

    df = pd.DataFrame(records)
    # garantir colunas
    for col in COLUNAS:
        if col not in df.columns:
            df[col] = ""

    df = df[COLUNAS].copy()

    df["Latitude"] = df["Latitude"].apply(to_float_safe)
    df["Longitude"] = df["Longitude"].apply(to_float_safe)

    # invalidar fora do brasil
    df.loc[~df["Latitude"].between(LAT_MIN, LAT_MAX, inclusive="both"), "Latitude"] = pd.NA
    df.loc[~df["Longitude"].between(LON_MIN, LON_MAX, inclusive="both"), "Longitude"] = pd.NA

    return df

def salvar_dados(df: pd.DataFrame):
    """
    Grava todos os dados no Sheets. Faz invalidação de cache com st.session_state.cache_key += 1
    Observação: ideal seria usar batch_update diferencial, mas para simplicidade e robustez
    gravamos toda a tabela (mantemos performance aceitável com cache).
    """
    try:
        df2 = df.copy()
        df2 = df2[COLUNAS].fillna("")
        WORKSHEET.clear()
        WORKSHEET.update([df2.columns.values.tolist()] + df2.values.tolist())
        # invalidar cache de dados
        st.session_state.cache_key = st.session_state.cache_key + 1
        # forçar recarregamento local na sessão
        st.experimental_rerun()
    except Exception as e:
        st.error("Erro ao salvar dados na planilha: " + str(e))

# -----------------------------
# COOKIES (login persistente)
# -----------------------------
cookies = EncryptedCookieManager(prefix=COOKIE_PREFIX, password=COOKIE_PASSWORD)
if not cookies.ready():
    # necessário para evitar erro no deploy
    st.stop()

USUARIOS_FILE = "usuarios.json"

def init_usuarios():
    try:
        with open(USUARIOS_FILE, "r") as f:
            usuarios = json.load(f)
            if not isinstance(usuarios, dict):
                raise ValueError("Formato inválido")
    except Exception:
        senha_hash = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
        usuarios = {"admin": {"senha": senha_hash, "nivel": "editor"}}
        with open(USUARIOS_FILE, "w") as f:
            json.dump(usuarios, f, indent=4)
    return usuarios

usuarios = init_usuarios()
usuario_cookie = cookies.get("usuario", "")
nivel_cookie = cookies.get("nivel", "")
logado = bool(usuario_cookie and nivel_cookie)
usuario_atual = usuario_cookie if logado else None
nivel_acesso = nivel_cookie if logado else None

# -----------------------------
# CONSTANTES LOCAIS
# -----------------------------
CAPITAIS_BRASILEIRAS = set([
    "Rio Branco-AC", "Maceió-AL", "Macapá-AP", "Manaus-AM", "Salvador-BA", "Fortaleza-CE",
    "Brasília-DF", "Vitória-ES", "Goiânia-GO", "São Luís-MA", "Cuiabá-MT", "Campo Grande-MS",
    "Belo Horizonte-MG", "Belém-PA", "João Pessoa-PB", "Curitiba-PR", "Recife-PE", "Teresina-PI",
    "Rio de Janeiro-RJ", "Natal-RN", "Porto Alegre-RS", "Boa Vista-RR", "Florianópolis-SC",
    "São Paulo-SP", "Aracaju-SE", "Palmas-TO"
])

def cidade_eh_capital(cidade: str, uf: str) -> bool:
    return f"{cidade}-{uf}" in CAPITAIS_BRASILEIRAS

# -----------------------------
# IBGE / GEO HELPERS (cache forte)
# -----------------------------
@st.cache_data(show_spinner=False)
def carregar_estados():
    resp = requests.get(IBGE_ESTADOS_URL, timeout=8)
    resp.raise_for_status()
    return sorted(resp.json(), key=lambda e: e["nome"])

@st.cache_data(show_spinner=False)
def carregar_cidades(uf: str):
    resp = requests.get(IBGE_CIDADES_URL.format(uf=uf), timeout=8)
    resp.raise_for_status()
    return sorted(resp.json(), key=lambda c: c["nome"])

@st.cache_resource(show_spinner=False)
def geojson_estados_cache():
    """GeoJSON dos estados (carregado 1 vez por processo)."""
    try:
        resp = requests.get(IBGE_MALHAS_ESTADOS, timeout=15)
        if resp.status_code == 200:
            geojson = resp.json()
            for feature in geojson.get("features", []):
                feature["properties"]["style"] = {
                    "color": "#000000", "weight": 3, "dashArray": "0", "fillOpacity": 0
                }
            return geojson
    except Exception:
        return None
    return None

@st.cache_data(show_spinner=False)
def obter_geojson_cidade_por_id(municipio_id: int):
    try:
        resp = requests.get(IBGE_MALHA_CIDADE.format(id=municipio_id), timeout=8)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        return None
    return None

# -----------------------------
# GEO: obter coordenadas (usado só no cadastro/edição)
# -----------------------------
def obter_coordenadas(cidade: str, estado_sigla: str, retries=2) -> Tuple[Optional[float], Optional[float]]:
    geolocator = Nominatim(user_agent="distribuidores_app", timeout=6)
    q = f"{cidade}, {estado_sigla}, Brasil"
    for attempt in range(retries + 1):
        try:
            loc = geolocator.geocode(q)
            if loc:
                lat = to_float_safe(loc.latitude)
                lon = to_float_safe(loc.longitude)
                if latlon_valid(lat, lon):
                    return lat, lon
                return None, None
            return None, None
        except (GeocoderTimedOut, GeocoderUnavailable):
            time.sleep(1 + attempt)
            continue
        except Exception:
            break
    return None, None

# -----------------------------
# UTIL: cor para distribuidor
# -----------------------------
def cor_distribuidor(nome: str) -> str:
    h = abs(hash(nome)) % 0xAAAAAA
    h += 0x111111
    return f"#{h:06X}"

# -----------------------------
# CRIAR MAPA (otimizado)
# -----------------------------
def criar_mapa(df: pd.DataFrame, filtro_distribuidores=None, zoom_to_state: Optional[dict]=None):
    default_location = [-14.2350, -51.9253]
    zoom_start = 5
    if zoom_to_state and isinstance(zoom_to_state, dict):
        center = zoom_to_state.get("center", default_location)
        zoom_start = zoom_to_state.get("zoom", 6)
        mapa = folium.Map(location=center, zoom_start=zoom_start, tiles="CartoDB positron")
    else:
        mapa = folium.Map(location=default_location, zoom_start=zoom_start, tiles="CartoDB positron")

    # Adiciona GeoJSON dos estados (cacheado)
    geo_estados = geojson_estados_cache()
    if geo_estados:
        try:
            folium.GeoJson(
                geo_estados,
                name="Divisas Estaduais",
                style_function=lambda f: f.get("properties", {}).get("style", {
                    "color": "#000000", "weight": 3, "fillOpacity": 0
                }),
                tooltip=folium.GeoJsonTooltip(fields=["nome"], aliases=["Estado:"])
            ).add_to(mapa)
        except Exception:
            pass

    # Decidir se vamos baixar malhas municipais (carregamento pesado) ou apenas marcadores
    # Condição: se número de features filtradas <= 6 OR apenas 1 distribuidor selecionado, renderiza malhas municipais.
    carregar_malhas = False
    try:
        nrows = 0 if df is None else len(df)
        if nrows <= 6 or (filtro_distribuidores and len(filtro_distribuidores) == 1):
            carregar_malhas = True
    except Exception:
        carregar_malhas = False

    # adicionar shapes (quando possível)
    for _, row in df.iterrows():
        if filtro_distribuidores and row["Distribuidor"] not in filtro_distribuidores:
            continue
        cidade = row.get("Cidade", "")
        estado = row.get("Estado", "")
        cor = cor_distribuidor(row.get("Distribuidor", ""))

        # tentar pegar geojson municipal APENAS quando carregar_malhas True
        geojson = None
        if carregar_malhas and cidade and estado:
            try:
                cidades_data = carregar_cidades(estado)
                cidade_info = next((c for c in cidades_data if c["nome"] == cidade), None)
                if cidade_info and "id" in cidade_info:
                    geojson = obter_geojson_cidade_por_id(int(cidade_info["id"]))
            except Exception:
                geojson = None

        if geojson and "features" in geojson:
            try:
                folium.GeoJson(
                    geojson,
                    style_function=lambda feature, cor=cor: {
                        "fillColor": cor, "color": "#666666", "weight": 1.0, "fillOpacity": 0.45
                    },
                    tooltip=f"{row.get('Distribuidor','')} ({cidade} - {estado})"
                ).add_to(mapa)
            except Exception:
                pass
        else:
            lat = row.get("Latitude", pd.NA)
            lon = row.get("Longitude", pd.NA)
            try:
                if pd.isna(lat) or pd.isna(lon):
                    continue
                if not latlon_valid(lat, lon):
                    continue
                folium.CircleMarker(
                    location=[float(lat), float(lon)],
                    radius=7,
                    color="#333333",
                    fill=True,
                    fill_color=cor,
                    fill_opacity=0.9,
                    popup=f"{row.get('Distribuidor','')} ({cidade} - {estado})"
                ).add_to(mapa)
            except Exception:
                continue

    folium.LayerControl().add_to(mapa)
    return mapa

# -----------------------------
# VALIDAÇÕES (telefone/email)
# -----------------------------
def validar_telefone(tel: str) -> bool:
    padrao = r'^\(\d{2}\) \d{4,5}-\d{4}$'
    return bool(re.match(padrao, str(tel or "").strip()))

def validar_email(email: str) -> bool:
    padrao = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(padrao, str(email or "").strip()))

# -----------------------------
# INTERFACE / LÓGICA PRINCIPAL
# -----------------------------
# carregar dados iniciais (usa cache)
df_global = carregar_dados(st.session_state.cache_key)

# garantir chaves session_state
if "cidade_busca" not in st.session_state:
    st.session_state.cidade_busca = ""
if "estado_filtro" not in st.session_state:
    st.session_state.estado_filtro = ""
if "distribuidores_selecionados" not in st.session_state:
    st.session_state.distribuidores_selecionados = []

# Login
if not logado:
    st.title("🔐 Login")
    usuario = st.text_input("Usuário")
    senha = st.text_input("Senha", type="password")
    if st.button("Entrar"):
        if usuario in usuarios and bcrypt.checkpw(senha.encode(), usuarios[usuario]["senha"].encode()):
            cookies["usuario"] = usuario
            cookies["nivel"] = usuarios[usuario]["nivel"]
            cookies.save()
            st.experimental_rerun()
        else:
            st.error("Usuário ou senha incorretos.")
    st.stop()

# Sidebar: usuário + logout + navegação
st.sidebar.write(f"👤 {usuario_atual} ({nivel_acesso})")
if st.sidebar.button("🚪 Sair"):
    cookies["usuario"] = ""
    cookies["nivel"] = ""
    cookies.save()
    st.experimental_rerun()

menu = ["Cadastro", "Lista / Editar / Excluir", "Mapa"]
choice = st.sidebar.radio("Navegação", menu)

# -----------------------------
# CADASTRO
# -----------------------------
if choice == "Cadastro" and nivel_cookie == "editor":
    st.header("Cadastrar Novo Distribuidor")
    col1, col2 = st.columns(2)
    with col1:
        estados = carregar_estados()
        siglas = [e["sigla"] for e in estados]
        estado_sel = st.selectbox("Estado", [""] + siglas)
        cidades = [c["nome"] for c in carregar_cidades(estado_sel)] if estado_sel else []
        cidades_sel = st.multiselect("Cidades", cidades)
    with col2:
        nome = st.text_input("Nome do Distribuidor")
        contato = st.text_input("Contato (formato: (XX) XXXXX-XXXX)")
        email = st.text_input("Email")

    if st.button("Adicionar Distribuidor"):
        if not nome.strip() or not contato.strip() or not email.strip() or not estado_sel or not cidades_sel:
            st.error("Preencha todos os campos!")
        elif not validar_telefone(contato.strip()):
            st.error("Contato inválido! Use o formato (XX) XXXXX-XXXX")
        elif not validar_email(email.strip()):
            st.error("Email inválido!")
        elif nome in df_global["Distribuidor"].tolist():
            st.error("Distribuidor já cadastrado!")
        else:
            # verificar cidades ocupadas (exclui capitais)
            cidades_ocupadas = []
            for c in cidades_sel:
                if c in df_global["Cidade"].tolist() and not cidade_eh_capital(c, estado_sel):
                    dist_existente = df_global.loc[df_global["Cidade"] == c, "Distribuidor"].iloc[0]
                    cidades_ocupadas.append(f"{c} (atualmente {dist_existente})")
            if cidades_ocupadas:
                st.error("As seguintes cidades já estão atribuídas:\n" + "\n".join(cidades_ocupadas))
            else:
                novos = []
                for c in cidades_sel:
                    lat, lon = obter_coordenadas(c, estado_sel)
                    # if geocode failed, deixa como NA (usuário pode editar depois)
                    lat_v = to_float_safe(lat)
                    lon_v = to_float_safe(lon)
                    if lat_v is not None and lon_v is not None and not latlon_valid(lat_v, lon_v):
                        lat_v, lon_v = None, None
                    novos.append([nome, contato, email, estado_sel, c, lat_v, lon_v])
                novo_df = pd.DataFrame(novos, columns=COLUNAS)
                df_global = pd.concat([df_global, novo_df], ignore_index=True)
                salvar_dados(df_global)  # salva e faz rerun via salvar_dados()

# -----------------------------
# LISTA / EDITAR / EXCLUIR
# -----------------------------
elif choice == "Lista / Editar / Excluir":
    st.header("Distribuidores Cadastrados")
    st.dataframe(df_global[["Distribuidor", "Contato", "Email", "Estado", "Cidade"]], use_container_width=True)

    if nivel_cookie == "editor":
        with st.expander("✏️ Editar"):
            if not df_global.empty:
                dist_edit = st.selectbox("Distribuidor", df_global["Distribuidor"].unique())
                dados = df_global[df_global["Distribuidor"] == dist_edit]
                nome_edit = st.text_input("Nome", value=dist_edit)
                contato_edit = st.text_input("Contato", value=dados.iloc[0]["Contato"])
                email_edit = st.text_input("Email", value=dados.iloc[0]["Email"])
                estado_edit = st.selectbox("Estado", sorted(df_global["Estado"].unique()),
                                          index=sorted(df_global["Estado"].unique()).index(dados.iloc[0]["Estado"]))
                cidades_disponiveis = [c["nome"] for c in carregar_cidades(estado_edit)]
                cidades_novas = st.multiselect("Cidades", cidades_disponiveis, default=dados["Cidade"].tolist())

                if st.button("Salvar Alterações"):
                    if not validar_telefone(contato_edit.strip()):
                        st.error("Contato inválido!")
                    elif not validar_email(email_edit.strip()):
                        st.error("Email inválido!")
                    else:
                        outras_linhas = df_global[df_global["Distribuidor"] != dist_edit]
                        cidades_ocupadas = []
                        for cidade in cidades_novas:
                            if cidade in outras_linhas["Cidade"].tolist() and not cidade_eh_capital(cidade, estado_edit):
                                dist_existente = outras_linhas.loc[outras_linhas["Cidade"] == cidade, "Distribuidor"].iloc[0]
                                cidades_ocupadas.append(f"{cidade} (atualmente {dist_existente})")
                        if cidades_ocupadas:
                            st.error("As seguintes cidades já estão atribuídas:\n" + "\n".join(cidades_ocupadas))
                        else:
                            # remover distribuidor antigo e re-criar com cidades novas
                            df_global = df_global[df_global["Distribuidor"] != dist_edit]
                            novos = []
                            for cidade in cidades_novas:
                                lat, lon = obter_coordenadas(cidade, estado_edit)
                                lat_v = to_float_safe(lat)
                                lon_v = to_float_safe(lon)
                                if lat_v is not None and lon_v is not None and not latlon_valid(lat_v, lon_v):
                                    lat_v, lon_v = None, None
                                novos.append([nome_edit, contato_edit, email_edit, estado_edit, cidade, lat_v, lon_v])
                            novo_df = pd.DataFrame(novos, columns=COLUNAS)
                            df_global = pd.concat([df_global, novo_df], ignore_index=True)
                            salvar_dados(df_global)

        with st.expander("🗑️ Excluir"):
            if not df_global.empty:
                dist_del = st.selectbox("Distribuidor para excluir", sorted(df_global["Distribuidor"].unique()))
                if st.button("Excluir Distribuidor"):
                    df_global = df_global[df_global["Distribuidor"] != dist_del]
                    salvar_dados(df_global)

# -----------------------------
# MAPA
# -----------------------------
elif choice == "Mapa":
    st.header("🗺️ Mapa de Distribuidores")

    # Sidebar filtros
    st.sidebar.markdown("### 🔎 Filtros do Mapa")

    # Estado filter
    estados = carregar_estados()
    siglas = [e["sigla"] for e in estados]
    estado_options = [""] + siglas
    estado_index = 0 if st.session_state.estado_filtro == "" else estado_options.index(st.session_state.estado_filtro)
    estado_filtro = st.sidebar.selectbox("Filtrar por Estado", estado_options, index=estado_index)
    st.session_state.estado_filtro = estado_filtro

    # Distribuidores options
    if estado_filtro:
        distribuidores_opcoes = df_global.loc[df_global["Estado"] == estado_filtro, "Distribuidor"].dropna().unique().tolist()
    else:
        distribuidores_opcoes = df_global["Distribuidor"].dropna().unique().tolist()
    distribuidores_opcoes = sorted(distribuidores_opcoes)

    distribuidores_selecionados = st.sidebar.multiselect(
        "Filtrar Distribuidores (opcional)",
        distribuidores_opcoes,
        default=st.session_state.distribuidores_selecionados
    )
    st.session_state.distribuidores_selecionados = [d for d in distribuidores_selecionados if d in distribuidores_opcoes]

    # Busca por cidade
    todas_cidades = []
    try:
        todas_cidades = [f"{c['nome']} - {c['microrregiao']['mesorregiao']['UF']['sigla']}" for e in estados for c in carregar_cidades(e["sigla"])]
    except Exception:
        # fallback: gerar a partir do df
        todas_cidades = sorted(set([f"{row['Cidade']} - {row['Estado']}" for _, row in df_global.iterrows() if row['Cidade']]))

    if estado_filtro:
        todas_cidades = [c for c in todas_cidades if c.endswith(f" - {estado_filtro}")]
    cidade_index = 0 if st.session_state.cidade_busca == "" else (todas_cidades.index(st.session_state.cidade_busca) + 1 if st.session_state.cidade_busca in todas_cidades else 0)
    cidade_selecionada_sidebar = st.sidebar.selectbox("Buscar Cidade", [""] + todas_cidades, index=cidade_index)
    if cidade_selecionada_sidebar:
        st.session_state.cidade_busca = cidade_selecionada_sidebar

    if st.sidebar.button("Limpar filtros"):
        st.session_state.estado_filtro = ""
        st.session_state.distribuidores_selecionados = []
        st.session_state.cidade_busca = ""

    # aplicar filtros
    df_filtro = df_global.copy()
    if st.session_state.estado_filtro:
        df_filtro = df_filtro[df_filtro["Estado"] == st.session_state.estado_filtro]
    if st.session_state.distribuidores_selecionados:
        df_filtro = df_filtro[df_filtro["Distribuidor"].isin(st.session_state.distribuidores_selecionados)]

    # busca por cidade tem prioridade de exibição de mensagem/tabela
    if st.session_state.cidade_busca:
        try:
            cidade_nome, estado_sigla = st.session_state.cidade_busca.split(" - ")
            df_cidade = df_global[
                (df_global["Cidade"].str.lower() == cidade_nome.lower()) &
                (df_global["Estado"].str.upper() == estado_sigla.upper())
            ]
        except Exception:
            df_cidade = pd.DataFrame(columns=COLUNAS)

        if df_cidade.empty:
            st.warning(f"❌ Nenhum distribuidor encontrado em **{st.session_state.cidade_busca}**.")
            # centrar no estado se houver
            zoom_to_state = None
            if st.session_state.estado_filtro:
                df_state = df_global[df_global["Estado"] == st.session_state.estado_filtro]
                lats = pd.to_numeric(df_state["Latitude"], errors="coerce").dropna()
                lons = pd.to_numeric(df_state["Longitude"], errors="coerce").dropna()
                lats = lats[(lats >= LAT_MIN) & (lats <= LAT_MAX)]
                lons = lons[(lons >= LON_MIN) & (lons <= LON_MAX)]
                if not lats.empty and not lons.empty:
                    center_lat = float(lats.mean())
                    center_lon = float(lons.mean())
                    lat_span = lats.max() - lats.min() if lats.max() != lats.min() else 0.1
                    lon_span = lons.max() - lons.min() if lons.max() != lons.min() else 0.1
                    span = max(lat_span, lon_span)
                    if span < 0.2:
                        zoom = 11
                    elif span < 1.0:
                        zoom = 9
                    elif span < 3.0:
                        zoom = 8
                    else:
                        zoom = 6
                    zoom_to_state = {"center": [center_lat, center_lon], "zoom": zoom}
                else:
                    zoom_to_state = {"center": [-14.2350, -51.9253], "zoom": 5}
            else:
                zoom_to_state = {"center": [-14.2350, -51.9253], "zoom": 5}

            mapa = criar_mapa(pd.DataFrame(columns=COLUNAS), filtro_distribuidores=None, zoom_to_state=zoom_to_state)
            st_folium(mapa, width=1200, height=700, returned_objects=[])
        else:
            st.success(f"✅ {len(df_cidade)} distribuidor(es) encontrado(s) em **{st.session_state.cidade_busca}**:")
            st.dataframe(df_cidade[["Distribuidor", "Contato", "Email"]].reset_index(drop=True), use_container_width=True)

            df_cidade_map = df_cidade.copy()
            if st.session_state.distribuidores_selecionados:
                df_cidade_map = df_cidade_map[df_cidade_map["Distribuidor"].isin(st.session_state.distribuidores_selecionados)]

            # calcular zoom centrado
            zoom_to_state = None
            lats = pd.to_numeric(df_cidade_map["Latitude"], errors="coerce").dropna()
            lons = pd.to_numeric(df_cidade_map["Longitude"], errors="coerce").dropna()
            lats = lats[(lats >= LAT_MIN) & (lats <= LAT_MAX)]
            lons = lons[(lons >= LON_MIN) & (lons <= LON_MAX)]
            if not lats.empty and not lons.empty:
                center_lat = float(lats.mean())
                center_lon = float(lons.mean())
                lat_span = lats.max() - lats.min() if lats.max() != lats.min() else 0.02
                lon_span = lons.max() - lons.min() if lons.max() != lons.min() else 0.02
                span = max(lat_span, lon_span)
                if span < 0.02:
                    zoom = 13
                elif span < 0.2:
                    zoom = 11
                elif span < 1.0:
                    zoom = 9
                else:
                    zoom = 8
                zoom_to_state = {"center": [center_lat, center_lon], "zoom": zoom}
            else:
                zoom_to_state = {"center": [-14.2350, -51.9253], "zoom": 5}

            mapa = criar_mapa(
                df_cidade_map,
                filtro_distribuidores=(st.session_state.distribuidores_selecionados if st.session_state.distribuidores_selecionados else None),
                zoom_to_state=zoom_to_state
            )
            st_folium(mapa, width=1200, height=700, returned_objects=[])
    else:
        # sem busca por cidade: mapa geral com filtros aplicados
        zoom_to_state = None
        if st.session_state.estado_filtro:
            df_state = df_global[df_global["Estado"] == st.session_state.estado_filtro]
            lats = pd.to_numeric(df_state["Latitude"], errors="coerce").dropna()
            lons = pd.to_numeric(df_state["Longitude"], errors="coerce").dropna()
            lats = lats[(lats >= LAT_MIN) & (lats <= LAT_MAX)]
            lons = lons[(lons >= LON_MIN) & (lons <= LON_MAX)]
            if not lats.empty and not lons.empty:
                center_lat = float(lats.mean())
                center_lon = float(lons.mean())
                lat_span = lats.max() - lats.min() if lats.max() != lats.min() else 0.1
                lon_span = lons.max() - lons.min() if lons.max() != lons.min() else 0.1
                span = max(lat_span, lon_span)
                if span < 0.2:
                    zoom = 11
                elif span < 1.0:
                    zoom = 9
                elif span < 3.0:
                    zoom = 8
                else:
                    zoom = 6
                zoom_to_state = {"center": [center_lat, center_lon], "zoom": zoom}
            else:
                zoom_to_state = {"center": [-14.2350, -51.9253], "zoom": 5}

        mapa = criar_mapa(
            df_filtro,
            filtro_distribuidores=(st.session_state.distribuidores_selecionados if st.session_state.distribuidores_selecionados else None),
            zoom_to_state=zoom_to_state
        )
        st_folium(mapa, width=1200, height=700, returned_objects=[])

# -----------------------------
# FIM
# -----------------------------
