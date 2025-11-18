# -------------------------------------------------------------
# DISTRIBUIDORES APP - STREAMLIT (GOOGLE SHEETS)
# Versão otimizada: filtros sidebar, busca cidade com mensagem/tabela,
# limpeza de filtros, zoom por estado robusto, sanitização lat/lon,
# clusters rápidos, cache agressivo e geocoding somente quando necessário.
# Base: https://docs.google.com/spreadsheets/d/1hxPKagOnMhBYI44G3vQHY_wQGv6iYTxHMd_0VLw2r-k (aba "Página1")
# -------------------------------------------------------------

import os
import json
import re
import time
import requests
import pandas as pd
import folium
import bcrypt
from functools import lru_cache
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut, GeocoderUnavailable

import streamlit as st
from streamlit_folium import st_folium
from streamlit_cookies_manager import EncryptedCookieManager

# Folium plugins
from folium.plugins import MarkerCluster

# Google Sheets
import gspread
from google.oauth2.service_account import Credentials
from google.auth.exceptions import DefaultCredentialsError, RefreshError

# -----------------------------
# CONFIG
# -----------------------------
st.set_page_config(page_title="Distribuidores", layout="wide")

SHEET_ID = "1hxPKagOnMhBYI44G3vQHY_wQGv6iYTxHMd_0VLw2r-k"
SHEET_NAME = "Página1"
COLUNAS = ["Distribuidor", "Contato", "Email", "Estado", "Cidade", "Latitude", "Longitude"]

# Scopes
SCOPE = [
    "https://spreadsheets.google.com/feeds",
    "https://www.googleapis.com/auth/drive",
]

# Reuse requests session (faster connections)
REQUESTS_SESSION = requests.Session()
REQUESTS_SESSION.headers.update({"User-Agent": "DistribuidoresApp/1.0 (+https://example.com)"})

# -----------------------------
# HELPERS / CACHES
# -----------------------------
# IBGE requests cached for performance
@st.cache_data(ttl=60 * 60)
def carregar_estados():
    url = "https://servicodados.ibge.gov.br/api/v1/localidades/estados"
    resp = REQUESTS_SESSION.get(url, timeout=10)
    resp.raise_for_status()
    return sorted(resp.json(), key=lambda e: e["nome"])

@st.cache_data(ttl=60 * 60)
def carregar_cidades(uf):
    url = f"https://servicodados.ibge.gov.br/api/v1/localidades/estados/{uf}/municipios"
    resp = REQUESTS_SESSION.get(url, timeout=10)
    resp.raise_for_status()
    return sorted(resp.json(), key=lambda c: c["nome"])

@st.cache_data(ttl=60 * 60 * 24)
def carregar_todas_cidades():
    cidades = []
    estados = carregar_estados()
    for estado in estados:
        uf = estado["sigla"]
        url = f"https://servicodados.ibge.gov.br/api/v1/localidades/estados/{uf}/municipios"
        resp = REQUESTS_SESSION.get(url, timeout=10)
        if resp.status_code == 200:
            for c in resp.json():
                cidades.append(f"{c['nome']} - {uf}")
    return sorted(cidades)

# GeoJSON de estados (cache grande) – usado como camada de fundo
@st.cache_data(ttl=60 * 60 * 24)
def obter_geojson_estados():
    url = (
        "https://servicodados.ibge.gov.br/api/v2/malhas/"
        "?formato=application/vnd.geo+json&qualidade=simplificada&incluir=estados"
    )
    try:
        resp = REQUESTS_SESSION.get(url, timeout=20)
        if resp.status_code == 200:
            geojson = resp.json()
            for feature in geojson.get("features", []):
                feature.setdefault("properties", {})
                feature["properties"]["style"] = {"color": "#000000", "weight": 2, "fillOpacity": 0}
            return geojson
    except Exception:
        return None
    return None

# GeoJSON cidade – guardamos no cache, mas LIMITAMOS quantas cidades vamos desenhar por mapa
@st.cache_data(ttl=60 * 60 * 24)
def obter_geojson_cidade(cidade, estado_sigla):
    try:
        cidades = carregar_cidades(estado_sigla)
    except Exception:
        return None
    info = next((c for c in cidades if c["nome"] == cidade), None)
    if not info:
        return None
    url = f"https://servicodados.ibge.gov.br/api/v2/malhas/{info['id']}?formato=application/vnd.geo+json&qualidade=intermediaria"
    try:
        resp = REQUESTS_SESSION.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        return None
    return None

# Geocode por cidade+estado (cache local para reduzir requests ao Nominatim)
@lru_cache(maxsize=512)
def geocode_cidade_estado(cidade, estado):
    if not cidade or not estado:
        return None
    geolocator = Nominatim(user_agent="distribuidores_app", timeout=6)
    try:
        loc = geolocator.geocode(f"{cidade}, {estado}, Brasil")
        if loc:
            return float(loc.latitude), float(loc.longitude)
    except Exception:
        return None
    return None

# Determina cor por distribuidor (estável)
def cor_distribuidor(nome):
    try:
        h = abs(hash(nome)) % 0xFFFFFF
        return f"#{h:06X}"
    except Exception:
        return "#3186cc"

# -----------------------------
# GOOGLE SHEETS – inicialização e I/O eficiente
# -----------------------------
GC = None
WORKSHEET = None

def init_gsheets():
    global GC, WORKSHEET
    if "gcp_service_account" not in st.secrets:
        st.error("❌ Google Service Account não configurada em st.secrets")
        st.stop()
    try:
        creds_dict = st.secrets["gcp_service_account"]
        creds = Credentials.from_service_account_info(creds_dict, scopes=SCOPE)
        GC = gspread.authorize(creds)
        sh = GC.open_by_key(SHEET_ID)
        try:
            WORKSHEET = sh.worksheet(SHEET_NAME)
        except gspread.WorksheetNotFound:
            WORKSHEET = sh.add_worksheet(title=SHEET_NAME, rows="1000", cols=str(len(COLUNAS)))
            WORKSHEET.update([COLUNAS])
    except Exception as e:
        st.error("Erro ao autenticar/abrir Sheets: " + str(e))
        st.stop()

init_gsheets()

# Carrega e sanitiza dados com vectorized ops (muito mais rápido que iterrows)
@st.cache_data(ttl=60)
def carregar_dados_from_sheet():
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
    for c in COLUNAS:
        if c not in df.columns:
            df[c] = ""
    df = df[COLUNAS].copy()

    # vectorized sanitization: replace commas, spaces, coerce to numeric
    def to_float_series(s):
        s = s.fillna("").astype(str).str.strip().str.replace(",", ".").str.replace(" ", "")
        s = s.replace({"": pd.NA})
        return pd.to_numeric(s, errors="coerce")

    df["Latitude"] = to_float_series(df["Latitude"])
    df["Longitude"] = to_float_series(df["Longitude"])

    # validate Brasil bounds
    df.loc[~df["Latitude"].between(-35.0, 6.0, inclusive="both"), "Latitude"] = pd.NA
    df.loc[~df["Longitude"].between(-82.0, -30.0, inclusive="both"), "Longitude"] = pd.NA

    return df

# Salva apenas quando necessário (batch update)
def salvar_dados_batch(df):
    try:
        df2 = df.copy().fillna("")
        WORKSHEET.clear()
        WORKSHEET.update([df2.columns.values.tolist()] + df2.values.tolist())
        # invalidate cache
        try:
            carregar_dados_from_sheet.clear()
        except Exception:
            pass
    except Exception as e:
        st.error("Erro ao salvar dados na planilha: " + str(e))

# -----------------------------
# COOKIES / LOGIN
# -----------------------------
cookies = EncryptedCookieManager(prefix="distribuidores_login", password="chave_secreta_segura_123")
if not cookies.ready():
    st.stop()

USUARIOS_FILE = "usuarios.json"

def init_usuarios():
    try:
        with open(USUARIOS_FILE, "r", encoding="utf-8") as f:
            usuarios = json.load(f)
            if not isinstance(usuarios, dict):
                raise ValueError("Formato inválido")
    except Exception:
        senha_hash = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
        usuarios = {"admin": {"senha": senha_hash, "nivel": "editor"}}
        with open(USUARIOS_FILE, "w", encoding="utf-8") as f:
            json.dump(usuarios, f, indent=4, ensure_ascii=False)
    return usuarios

usuarios = init_usuarios()
usuario_cookie = cookies.get("usuario", "")
nivel_cookie = cookies.get("nivel", "")
logado = usuario_cookie != "" and nivel_cookie != ""
usuario_atual = usuario_cookie if logado else None
nivel_acesso = nivel_cookie if logado else None

if not logado:
    st.title("🔐 Login de Acesso")
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

st.sidebar.write(f"👤 {usuario_atual} ({nivel_acesso})")
if st.sidebar.button("🚪 Sair"):
    cookies["usuario"] = ""
    cookies["nivel"] = ""
    cookies.save()
    st.rerun()

# -----------------------------
# Utilitários
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

STATE_CENTROIDS = {
    "AC": {"center": [-8.77, -70.55], "zoom": 6},
    "AL": {"center": [-9.62, -36.82], "zoom": 7},
    "AP": {"center": [1.41, -51.77], "zoom": 6},
    "AM": {"center": [-3.07, -61.67], "zoom": 5},
    "BA": {"center": [-13.29, -41.71], "zoom": 6},
    "CE": {"center": [-5.20, -39.53], "zoom": 7},
    "DF": {"center": [-15.79, -47.88], "zoom": 10},
    "ES": {"center": [-19.19, -40.34], "zoom": 8},
    "GO": {"center": [-16.64, -49.31], "zoom": 7},
    "MA": {"center": [-2.55, -44.30], "zoom": 6},
    "MT": {"center": [-12.64, -55.42], "zoom": 5},
    "MS": {"center": [-20.51, -54.54], "zoom": 6},
    "MG": {"center": [-18.10, -44.38], "zoom": 6},
    "PA": {"center": [-5.53, -52.29], "zoom": 5},
    "PB": {"center": [-7.06, -35.55], "zoom": 7},
    "PR": {"center": [-24.89, -51.55], "zoom": 7},
    "PE": {"center": [-8.28, -35.07], "zoom": 7},
    "PI": {"center": [-7.71, -42.73], "zoom": 6},
    "RJ": {"center": [-22.90, -43.20], "zoom": 8},
    "RN": {"center": [-5.22, -36.52}, "zoom": 7},
    "RS": {"center": [-30.03, -51.23], "zoom": 6},
    "RO": {"center": [-10.83, -63.34], "zoom": 6},
    "RR": {"center": [2.82, -60.67], "zoom": 6},
    "SC": {"center": [-27.33, -49.44], "zoom": 7},
    "SP": {"center": [-22.19, -48.79], "zoom": 7},
    "SE": {"center": [-10.90, -37.07], "zoom": 7},
    "TO": {"center": [-9.45, -48.26], "zoom": 6},
}

# -----------------------------
# Criar mapa otimizado
# -----------------------------
def criar_mapa(df, filtro_distribuidores=None, zoom_to_state=None, max_city_geojson=20):
    # centro padrão BR
    default_location = [-14.2350, -51.9253]
    zoom_start = 5
    if zoom_to_state and isinstance(zoom_to_state, dict):
        center = zoom_to_state.get("center", default_location)
        zoom_start = zoom_to_state.get("zoom", 6)
    else:
        center = default_location

    mapa = folium.Map(location=center, zoom_start=zoom_start, tiles="CartoDB positron")

    # background states geojson (lightweight)
    geo_estados = obter_geojson_estados()
    if geo_estados:
        try:
            folium.GeoJson(
                geo_estados,
                name="Estados",
                style_function=lambda f: {"color": "#000000", "weight": 2, "fillOpacity": 0},
            ).add_to(mapa)
        except Exception:
            pass

    # aplicar filtro de distribuidores
    if filtro_distribuidores is not None:
        df = df[df["Distribuidor"].isin(filtro_distribuidores)]

    # prefiltra coords válidas
    df_valid = df.dropna(subset=["Latitude", "Longitude"]).copy()
    df_valid = df_valid[(df_valid["Latitude"].between(-35.0, 6.0)) & (df_valid["Longitude"].between(-82.0, -30.0))]

    # adicionar geojsons de cidades (limitado) — só para cidades com polygon disponível
    cidades_unicas = df[["Cidade", "Estado"]].drop_duplicates().dropna()
    added = 0
    for _, r in cidades_unicas.iterrows():
        if added >= max_city_geojson:
            break
        cidade = r["Cidade"]
        estado = r["Estado"]
        if not cidade or not estado:
            continue
        geo = obter_geojson_cidade(cidade, estado)
        if geo and "features" in geo:
            try:
                folium.GeoJson(
                    geo,
                    tooltip=f"{cidade} - {estado}",
                    style_function=lambda feature, ec=cor_distribuidor(cidade): {"fillColor": ec, "color": "#666", "weight": 0.8, "fillOpacity": 0.35},
                ).add_to(mapa)
                added += 1
            except Exception:
                continue

    # cluster rápido para muitos pontos
    pontos = []
    for _, row in df_valid.iterrows():
        pontos.append((float(row["Latitude"]), float(row["Longitude"]), row.get("Distribuidor", ""), row.get("Cidade", ""), row.get("Estado", "")))

    if pontos:
        if len(pontos) > 300:
            cluster = MarkerCluster(name="Distribuidores").add_to(mapa)
            for lat, lon, nome, cid, uf in pontos:
                folium.CircleMarker(
                    location=[lat, lon],
                    radius=5,
                    color="#333",
                    fill=True,
                    fill_color=cor_distribuidor(nome),
                    fill_opacity=0.9,
                    popup=f"{nome} ({cid} - {uf})",
                ).add_to(cluster)
        else:
            for lat, lon, nome, cid, uf in pontos:
                folium.CircleMarker(
                    location=[lat, lon],
                    radius=7,
                    color="#333",
                    fill=True,
                    fill_color=cor_distribuidor(nome),
                    fill_opacity=0.9,
                    popup=f"{nome} ({cid} - {uf})",
                ).add_to(mapa)

    folium.LayerControl().add_to(mapa)
    return mapa

# -----------------------------
# Validações simples
# -----------------------------
telefone_re = re.compile(r'^\(\d{2}\) \d{4,5}-\d{4}$')
email_re = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')

def validar_telefone(tel):
    return bool(telefone_re.match(str(tel)))

def validar_email(email):
    return bool(email_re.match(str(email)))

# -----------------------------
# Sessão e carregamento
# -----------------------------
if "df" not in st.session_state:
    st.session_state.df = carregar_dados_from_sheet()
if "cidade_busca" not in st.session_state:
    st.session_state.cidade_busca = ""
if "estado_filtro" not in st.session_state:
    st.session_state.estado_filtro = ""
if "distribuidores_selecionados" not in st.session_state:
    st.session_state.distribuidores_selecionados = []

menu = ["Cadastro", "Lista / Editar / Excluir", "Mapa"]
choice = st.sidebar.radio("Navegação", menu)

# -----------------------------
# CADASTRO
# -----------------------------
if choice == "Cadastro" and nivel_acesso == "editor":
    st.subheader("Cadastrar Novo Distribuidor")
    col1, col2 = st.columns(2)
    with col1:
        estados = carregar_estados()
        siglas = [e["sigla"] for e in estados]
        estado_sel = st.selectbox("Estado", siglas)
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
        elif nome in st.session_state.df["Distribuidor"].tolist():
            st.error("Distribuidor já cadastrado!")
        else:
            novos = []
            for c in cidades_sel:
                # reutiliza coords já existentes quando possível
                existing = st.session_state.df[(st.session_state.df["Cidade"] == c) & (st.session_state.df["Estado"] == estado_sel)]
                if not existing.empty and pd.notna(existing.iloc[0]["Latitude"]) and pd.notna(existing.iloc[0]["Longitude"]):
                    lat_v = float(existing.iloc[0]["Latitude"]) 
                    lon_v = float(existing.iloc[0]["Longitude"])
                else:
                    geo = geocode_cidade_estado(c, estado_sel)
                    if geo:
                        lat_v, lon_v = geo
                        if not (-35.0 <= lat_v <= 6.0 and -82.0 <= lon_v <= -30.0):
                            lat_v, lon_v = pd.NA, pd.NA
                    else:
                        lat_v, lon_v = pd.NA, pd.NA
                novos.append([nome, contato, email, estado_sel, c, lat_v, lon_v])
            novo_df = pd.DataFrame(novos, columns=COLUNAS)
            st.session_state.df = pd.concat([st.session_state.df, novo_df], ignore_index=True)
            salvar_dados_batch(st.session_state.df)
            st.success(f"✅ Distribuidor '{nome}' adicionado!")

# -----------------------------
# LISTA / EDITAR / EXCLUIR
# -----------------------------
elif choice == "Lista / Editar / Excluir":
    st.subheader("Distribuidores Cadastrados")
    st.dataframe(st.session_state.df[["Distribuidor", "Contato", "Email", "Estado", "Cidade"]], use_container_width=True)

    if nivel_acesso == "editor":
        with st.expander("✏️ Editar"):
            if not st.session_state.df.empty:
                dist_edit = st.selectbox("Distribuidor", st.session_state.df["Distribuidor"].unique())
                dados = st.session_state.df[st.session_state.df["Distribuidor"] == dist_edit]
                nome_edit = st.text_input("Nome", value=dist_edit)
                contato_edit = st.text_input("Contato", value=dados.iloc[0]["Contato"])
                email_edit = st.text_input("Email", value=dados.iloc[0]["Email"]) 
                estado_edit = st.selectbox(
                    "Estado",
                    sorted(st.session_state.df["Estado"].unique()),
                    index=sorted(st.session_state.df["Estado"].unique()).index(dados.iloc[0]["Estado"])
                )
                cidades_disponiveis = [c["nome"] for c in carregar_cidades(estado_edit)]
                cidades_novas = st.multiselect("Cidades", cidades_disponiveis, default=dados["Cidade"].tolist())

                if st.button("Salvar Alterações"):
                    if not validar_telefone(contato_edit.strip()):
                        st.error("Contato inválido! Use o formato (XX) XXXXX-XXXX")
                    elif not validar_email(email_edit.strip()):
                        st.error("Email inválido!")
                    else:
                        outras_linhas = st.session_state.df[st.session_state.df["Distribuidor"] != dist_edit]
                        cidades_ocupadas = []
                        for cidade in cidades_novas:
                            if cidade in outras_linhas["Cidade"].tolist() and not cidade_eh_capital(cidade, estado_edit):
                                dist_existente = outras_linhas.loc[outras_linhas["Cidade"] == cidade, "Distribuidor"].iloc[0]
                                cidades_ocupadas.append(f"{cidade} (atualmente atribuída a {dist_existente})")
                        if cidades_ocupadas:
                            st.error("As seguintes cidades já estão atribuídas a outros distribuidores:\n" + "\n".join(cidades_ocupadas))
                        else:
                            st.session_state.df = st.session_state.df[st.session_state.df["Distribuidor"] != dist_edit]
                            novos = []
                            for cidade in cidades_novas:
                                existing = st.session_state.df[(st.session_state.df["Cidade"] == cidade) & (st.session_state.df["Estado"] == estado_edit)]
                                if not existing.empty and pd.notna(existing.iloc[0]["Latitude"]) and pd.notna(existing.iloc[0]["Longitude"]):
                                    lat_v = float(existing.iloc[0]["Latitude"]) 
                                    lon_v = float(existing.iloc[0]["Longitude"])
                                else:
                                    geo = geocode_cidade_estado(cidade, estado_edit)
                                    if geo:
                                        lat_v, lon_v = geo
                                        if not (-35.0 <= lat_v <= 6.0 and -82.0 <= lon_v <= -30.0):
                                            lat_v, lon_v = pd.NA, pd.NA
                                    else:
                                        lat_v, lon_v = pd.NA, pd.NA
                                novos.append([nome_edit, contato_edit, email_edit, estado_edit, cidade, lat_v, lon_v])
                            novo_df = pd.DataFrame(novos, columns=COLUNAS)
                            st.session_state.df = pd.concat([st.session_state.df, novo_df], ignore_index=True)
                            salvar_dados_batch(st.session_state.df)
                            st.success("✅ Alterações salvas!")

        with st.expander("🗑️ Excluir"):
            if not st.session_state.df.empty:
                dist_del = st.selectbox("Distribuidor para excluir", st.session_state.df["Distribuidor"].unique())
                if st.button("Excluir Distribuidor"):
                    st.session_state.df = st.session_state.df[st.session_state.df["Distribuidor"] != dist_del]
                    salvar_dados_batch(st.session_state.df)
                    st.success(f"🗑️ '{dist_del}' removido!")

# -----------------------------
# MAPA (filtros na sidebar, busca cidade com mensagem/tabela, limpeza de filtros, zoom robusto)
# -----------------------------
elif choice == "Mapa":
    st.subheader("🗺️ Mapa de Distribuidores")

    st.sidebar.markdown("### 🔎 Filtros do Mapa")

    # Estado selectbox com opção vazia
    estados = carregar_estados()
    siglas = [e["sigla"] for e in estados]
    estado_options = [""] + siglas
    estado_index = 0 if st.session_state.estado_filtro == "" else estado_options.index(st.session_state.estado_filtro)
    estado_filtro = st.sidebar.selectbox("Filtrar por Estado", estado_options, index=estado_index)
    st.session_state.estado_filtro = estado_filtro

    # Multiselect distribuidores
    if estado_filtro:
        distribuidores_opcoes = st.session_state.df.loc[st.session_state.df["Estado"] == estado_filtro, "Distribuidor"].dropna().unique().tolist()
    else:
        distribuidores_opcoes = st.session_state.df["Distribuidor"].dropna().unique().tolist()
    distribuidores_opcoes = sorted(distribuidores_opcoes)

    distrib_selecionados = st.sidebar.multiselect("Filtrar Distribuidores (opcional)", distribuidores_opcoes, default=st.session_state.distribuidores_selecionados)
    st.session_state.distribuidores_selecionados = [d for d in distrib_selecionados if d in distribuidores_opcoes]

    # Busca por cidade (com lista filtrada)
    todas_cidades = carregar_todas_cidades()
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

    # aplicar filtros combinados
    df_filtro = st.session_state.df.copy()
    if st.session_state.estado_filtro:
        df_filtro = df_filtro[df_filtro["Estado"] == st.session_state.estado_filtro]
    if st.session_state.distribuidores_selecionados:
        df_filtro = df_filtro[df_filtro["Distribuidor"].isin(st.session_state.distribuidores_selecionados)]

    # busca por cidade prioritária (mensagem + tabela)
    if st.session_state.cidade_busca:
        try:
            cidade_nome, estado_sigla = st.session_state.cidade_busca.split(" - ")
            df_cidade = st.session_state.df[(st.session_state.df["Cidade"].str.lower() == cidade_nome.lower()) & (st.session_state.df["Estado"].str.upper() == estado_sigla.upper())]
        except Exception:
            df_cidade = pd.DataFrame(columns=COLUNAS)

        if df_cidade.empty:
            st.warning(f"❌ Nenhum distribuidor encontrado em **{st.session_state.cidade_busca}**.")
            # centra no estado se escolhido, senão Brasil
            zoom_to_state = None
            if st.session_state.estado_filtro:
                df_state = st.session_state.df[st.session_state.df["Estado"] == st.session_state.estado_filtro]
                lats = pd.to_numeric(df_state["Latitude"], errors="coerce").dropna()
                lons = pd.to_numeric(df_state["Longitude"], errors="coerce").dropna()
                lats = lats[(lats >= -35.0) & (lats <= 6.0)]
                lons = lons[(lons >= -82.0) & (lons <= -30.0)]
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
                    zoom_to_state = STATE_CENTROIDS.get(st.session_state.estado_filtro, {"center": [-14.2350, -51.9253], "zoom": 5})
            else:
                zoom_to_state = {"center": [-14.2350, -51.9253], "zoom": 5}

            mapa = criar_mapa(pd.DataFrame(columns=COLUNAS), filtro_distribuidores=None, zoom_to_state=zoom_to_state)
            st_folium(mapa, width=1200, height=700)
        else:
            st.success(f"✅ {len(df_cidade)} distribuidor(es) encontrado(s) em **{st.session_state.cidade_busca}**:")
            st.dataframe(df_cidade[["Distribuidor", "Contato", "Email"]].reset_index(drop=True), use_container_width=True)

            df_cidade_map = df_cidade.copy()
            if st.session_state.distribuidores_selecionados:
                df_cidade_map = df_cidade_map[df_cidade_map["Distribuidor"].isin(st.session_state.distribuidores_selecionados)]

            lats = pd.to_numeric(df_cidade_map["Latitude"], errors="coerce").dropna()
            lons = pd.to_numeric(df_cidade_map["Longitude"], errors="coerce").dropna()
            lats = lats[(lats >= -35.0) & (lats <= 6.0)]
            lons = lons[(lons >= -82.0) & (lons <= -30.0)]
            zoom_to_state = None
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
                zoom_to_state = STATE_CENTROIDS.get(st.session_state.estado_filtro, {"center": [-14.2350, -51.9253], "zoom": 5})

            mapa = criar_mapa(df_cidade_map, filtro_distribuidores=(st.session_state.distribuidores_selecionados if st.session_state.distribuidores_selecionados else None), zoom_to_state=zoom_to_state)
            st_folium(mapa, width=1200, height=700)
    else:
        # sem busca por cidade: mapa geral
        zoom_to_state = None
        if st.session_state.estado_filtro:
            df_state = st.session_state.df[st.session_state.df["Estado"] == st.session_state.estado_filtro]
            lats = pd.to_numeric(df_state["Latitude"], errors="coerce").dropna()
            lons = pd.to_numeric(df_state["Longitude"], errors="coerce").dropna()
            lats = lats[(lats >= -35.0) & (lats <= 6.0)]
            lons = lons[(lons >= -82.0) & (lons <= -30.0)]
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
                zoom_to_state = STATE_CENTROIDS.get(st.session_state.estado_filtro, {"center": [-14.2350, -51.9253], "zoom": 5})

        mapa = criar_mapa(df_filtro, filtro_distribuidores=(st.session_state.distribuidores_selecionados if st.session_state.distribuidores_selecionados else None), zoom_to_state=zoom_to_state)
        st_folium(mapa, width=1200, height=700)

# -----------------------------
# FIM
# -----------------------------
