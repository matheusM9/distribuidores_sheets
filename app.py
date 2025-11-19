# app.py
# -------------------------------------------------------------
# DISTRIBUIDORES APP - STREAMLIT (GOOGLE SHEETS)
# Versão otimizada — gera LAT/LON automaticamente e salva (uma vez)
# -------------------------------------------------------------

import json
import time
import re
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

# Geocoding (used only to generate missing lat/lon)
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut, GeocoderUnavailable

# -----------------------------
# CONFIGURAÇÕES
# -----------------------------
st.set_page_config(page_title="Distribuidores", layout="wide")

SHEET_ID = "1hxPKagOnMhBYI44G3vQHY_wQGv6iYTxHMd_0VLw2r-k"
SHEET_NAME = "Página1"
COLUNAS_BASE = ["Distribuidor", "Contato", "Email", "Estado", "Cidade"]
COLUNAS = COLUNAS_BASE + ["Latitude", "Longitude"]

# Cookie config
COOKIE_PREFIX = "distribuidores_login"
COOKIE_PASSWORD = "chave_secreta_segura_123"  # troque para algo seguro em produção

# Brazil bounds
LAT_MIN, LAT_MAX = -35.0, 6.0
LON_MIN, LON_MAX = -82.0, -30.0

# IBGE endpoints (used in other versions; kept for reference)
IBGE_ESTADOS_URL = "https://servicodados.ibge.gov.br/api/v1/localidades/estados"
IBGE_CIDADES_URL = "https://servicodados.ibge.gov.br/api/v1/localidades/estados/{uf}/municipios"

# -----------------------------
# UTIL: lat/lon helpers
# -----------------------------
def to_float_safe(x) -> Optional[float]:
    if x is None:
        return None
    if isinstance(x, (int, float)):
        return float(x)
    s = str(x).strip()
    if s == "" or s.lower() in ("na", "n/a", "none"):
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
# INIT: Google Sheets client (st.secrets preferred)
# -----------------------------
@st.cache_resource(show_spinner=False)
def init_worksheet():
    try:
        scopes = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
        if "gcp_service_account" in st.secrets:
            creds_info = st.secrets["gcp_service_account"]
            creds = Credentials.from_service_account_info(creds_info, scopes=scopes)
        else:
            # fallback to local file (dev)
            creds = Credentials.from_service_account_file("credentials.json", scopes=scopes)
        gc = gspread.authorize(creds)
        sh = gc.open_by_key(SHEET_ID)
        try:
            ws = sh.worksheet(SHEET_NAME)
        except gspread.WorksheetNotFound:
            ws = sh.add_worksheet(title=SHEET_NAME, rows="1000", cols=str(len(COLUNAS)))
            ws.update([COLUNAS])
        return ws
    except Exception as e:
        st.error("Erro ao inicializar Google Sheets. Verifique credenciais.\n" + str(e))
        st.stop()

WORKSHEET = init_worksheet()

# -----------------------------
# CACHE: dados e IBGE (rápido)
# -----------------------------
if "cache_key" not in st.session_state:
    st.session_state.cache_key = 0  # increment when we write

@st.cache_data(show_spinner=False)
def carregar_dados(cache_key: int) -> pd.DataFrame:
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
    # ensure columns
    for col in COLUNAS:
        if col not in df.columns:
            df[col] = ""
    df = df[COLUNAS].copy()

    # sanitize lat/lon
    df["Latitude"] = df["Latitude"].apply(to_float_safe)
    df["Longitude"] = df["Longitude"].apply(to_float_safe)

    # invalidate out-of-BR coords
    df.loc[~df["Latitude"].between(LAT_MIN, LAT_MAX, inclusive="both"), "Latitude"] = pd.NA
    df.loc[~df["Longitude"].between(LON_MIN, LON_MAX, inclusive="both"), "Longitude"] = pd.NA

    return df

# -----------------------------
# Função para gravar de volta (escreve toda a tabela - simples e robusto)
# -----------------------------
def salvar_dados_sheet(df: pd.DataFrame):
    try:
        df2 = df.copy()
        df2 = df2[COLUNAS].fillna("")
        WORKSHEET.clear()
        WORKSHEET.update([df2.columns.values.tolist()] + df2.values.tolist())
        # invalidate cache
        st.session_state.cache_key = st.session_state.cache_key + 1
    except Exception as e:
        st.error("Erro ao salvar dados no Sheets: " + str(e))

# -----------------------------
# COOKIES e usuários
# -----------------------------
cookies = EncryptedCookieManager(prefix=COOKIE_PREFIX, password=COOKIE_PASSWORD)
if not cookies.ready():
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
# IBGE helpers (cached)
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

# -----------------------------
# Geocode: gerar lat/lon por "Cidade, UF, Brasil"
# (usado apenas para preencher faltantes; respeita retries)
# -----------------------------
def geocode_city(cidade: str, uf: str, retries: int = 2, delay: float = 1.0) -> Tuple[Optional[float], Optional[float]]:
    if not cidade or not uf:
        return None, None
    geolocator = Nominatim(user_agent="distribuidores_app", timeout=6)
    q = f"{cidade}, {uf}, Brasil"
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
            time.sleep(delay * (attempt + 1))
            continue
        except Exception:
            break
    return None, None

# -----------------------------
# Atualizar coordenadas faltantes (UMA VEZ)
# -----------------------------
def atualizar_coordenadas_once(df: pd.DataFrame) -> pd.DataFrame:
    """
    Percorre df e gera lat/lon onde ausentes. Salva de volta no Sheets apenas se houver alterações.
    Retorna df atualizado (com mudanças em memória).
    """
    df = df.copy()
    precisa_salvar = False
    for idx, row in df.iterrows():
        lat = to_float_safe(row.get("Latitude"))
        lon = to_float_safe(row.get("Longitude"))
        if lat is None or lon is None:
            cidade = row.get("Cidade", "")
            estado = row.get("Estado", "")
            if cidade and estado:
                # attempt geocode
                lat_g, lon_g = geocode_city(cidade, estado)
                if lat_g is not None and lon_g is not None:
                    df.at[idx, "Latitude"] = lat_g
                    df.at[idx, "Longitude"] = lon_g
                    precisa_salvar = True
                else:
                    # leave as None (user can edit)
                    df.at[idx, "Latitude"] = pd.NA
                    df.at[idx, "Longitude"] = pd.NA
    if precisa_salvar:
        salvar_dados_sheet(df)
    return df

# -----------------------------
# Util: cor para distribuidor
# -----------------------------
def cor_distribuidor(nome: str) -> str:
    h = abs(hash(nome)) % 0xAAAAAA
    h += 0x111111
    return f"#{h:06X}"

# -----------------------------
# Map builder (optimized: draw state borders once; municipal malhas only when small set)
# -----------------------------
@st.cache_resource(show_spinner=False)
def geojson_estados_cache():
    try:
        url = ("https://servicodados.ibge.gov.br/api/v2/malhas/"
               "?formato=application/vnd.geo+json&qualidade=simplificada&incluir=estados")
        resp = requests.get(url, timeout=12)
        if resp.status_code == 200:
            geojson = resp.json()
            for feature in geojson.get("features", []):
                feature["properties"]["style"] = {"color": "#000000", "weight": 3, "dashArray": "0", "fillOpacity": 0}
            return geojson
    except Exception:
        return None
    return None

def criar_mapa(df: pd.DataFrame, filtro_distribuidores=None, zoom_to_state: Optional[dict] = None):
    default_loc = [-14.2350, -51.9253]
    zoom_start = 5
    if zoom_to_state and isinstance(zoom_to_state, dict):
        center = zoom_to_state.get("center", default_loc)
        zoom_start = zoom_to_state.get("zoom", 6)
        mapa = folium.Map(location=center, zoom_start=zoom_start, tiles="CartoDB positron")
    else:
        mapa = folium.Map(location=default_loc, zoom_start=zoom_start, tiles="CartoDB positron")

    # states geojson (cached)
    geo_est = geojson_estados_cache()
    if geo_est:
        try:
            folium.GeoJson(
                geo_est,
                name="Divisas Estaduais",
                style_function=lambda f: f.get("properties", {}).get("style", {"color": "#000000", "weight": 3, "fillOpacity": 0}),
                tooltip=folium.GeoJsonTooltip(fields=["nome"], aliases=["Estado:"])
            ).add_to(mapa)
        except Exception:
            pass

    # Decide whether to draw municipal malhas (heavy)
    carregar_malhas = False
    try:
        n = 0 if df is None else len(df)
        if n <= 6 or (filtro_distribuidores and len(filtro_distribuidores) == 1):
            carregar_malhas = True
    except Exception:
        carregar_malhas = False

    for _, row in df.iterrows():
        if filtro_distribuidores and row["Distribuidor"] not in filtro_distribuidores:
            continue
        cidade = row.get("Cidade", "")
        estado = row.get("Estado", "")
        cor = cor_distribuidor(row.get("Distribuidor", ""))

        geojson = None
        if carregar_malhas and cidade and estado:
            try:
                cidades = carregar_cidades(estado)
                cidade_info = next((c for c in cidades if c["nome"] == cidade), None)
                if cidade_info and "id" in cidade_info:
                    mid = int(cidade_info["id"])
                    url = (f"https://servicodados.ibge.gov.br/api/v2/malhas/{mid}"
                           "?formato=application/vnd.geo+json&qualidade=intermediaria")
                    resp = requests.get(url, timeout=8)
                    if resp.status_code == 200:
                        geojson = resp.json()
            except Exception:
                geojson = None

        if geojson and "features" in geojson:
            try:
                folium.GeoJson(
                    geojson,
                    style_function=lambda feature, cor=cor: {"fillColor": cor, "color": "#666666", "weight": 1.2, "fillOpacity": 0.55},
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
# Validações
# -----------------------------
def validar_telefone(tel: str) -> bool:
    padrao = r'^\(\d{2}\) \d{4,5}-\d{4}$'
    return bool(re.match(padrao, str(tel or "").strip()))

def validar_email(email: str) -> bool:
    padrao = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(padrao, str(email or "").strip()))

# -----------------------------
# Aplicação (UI)
# -----------------------------
# Carrega dados (cache)
df = carregar_dados(st.session_state.cache_key)

# Atualiza coordenadas faltantes (apenas uma vez por execução quando necessário)
# Nota: salvar_dados_sheet incrementa cache_key para invalidar cache em execuções futuras.
df = atualizar_coordenadas_once(df)

# Garantir session_state keys
if "estado_filtro" not in st.session_state:
    st.session_state.estado_filtro = ""
if "cidade_busca" not in st.session_state:
    st.session_state.cidade_busca = ""
if "distribuidores_selecionados" not in st.session_state:
    st.session_state.distribuidores_selecionados = []

# Login
if not logado:
    st.title("🔐 Login de Acesso")
    usuario = st.text_input("Usuário")
    senha = st.text_input("Senha", type="password")
    if st.button("Entrar"):
        if usuario in usuarios and bcrypt.checkpw(senha.encode(), usuarios[usuario]["senha"].encode()):
            cookies["usuario"] = usuario
            cookies["nivel"] = usuarios[usuario]["nivel"]
            cookies.save()
            st.experimental_rerun()
        else:
            st.error("Usuário ou senha incorretos!")
    st.stop()

st.sidebar.write(f"👤 {usuario_atual} ({nivel_acesso})")
if st.sidebar.button("🚪 Sair"):
    cookies["usuario"] = ""
    cookies["nivel"] = ""
    cookies.save()
    st.experimental_rerun()

menu = ["Cadastro", "Lista / Editar / Excluir", "Mapa"]
choice = st.sidebar.radio("Navegação", menu)

# CADASTRO
if choice == "Cadastro" and nivel_cookie == "editor":
    st.subheader("Cadastrar Novo Distribuidor")
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
        elif nome in df["Distribuidor"].tolist():
            st.error("Distribuidor já cadastrado!")
        else:
            cidades_ocupadas = []
            for c in cidades_sel:
                if c in df["Cidade"].tolist() and not (f"{c}-{estado_sel}" in set()):
                    dist_existente = df.loc[df["Cidade"] == c, "Distribuidor"].iloc[0]
                    cidades_ocupadas.append(f"{c} (atualmente atribuída a {dist_existente})")
            if cidades_ocupadas:
                st.error("As seguintes cidades já estão atribuídas a outros distribuidores:\n" + "\n".join(cidades_ocupadas))
            else:
                novos = []
                for c in cidades_sel:
                    lat, lon = geocode_city(c, estado_sel)
                    lat_v = to_float_safe(lat)
                    lon_v = to_float_safe(lon)
                    if lat_v is not None and lon_v is not None and not latlon_valid(lat_v, lon_v):
                        lat_v, lon_v = None, None
                    novos.append([nome, contato, email, estado_sel, c, lat_v, lon_v])
                novo_df = pd.DataFrame(novos, columns=COLUNAS)
                df = pd.concat([df, novo_df], ignore_index=True)
                salvar_dados_sheet(df)
                st.success(f"✅ Distribuidor '{nome}' adicionado!")

# LISTA / EDITAR / EXCLUIR
elif choice == "Lista / Editar / Excluir":
    st.subheader("Distribuidores Cadastrados")
    st.dataframe(df[["Distribuidor", "Contato", "Email", "Estado", "Cidade"]], use_container_width=True)

    if nivel_cookie == "editor":
        with st.expander("✏️ Editar"):
            if not df.empty:
                dist_edit = st.selectbox("Distribuidor", df["Distribuidor"].unique())
                dados = df[df["Distribuidor"] == dist_edit]
                nome_edit = st.text_input("Nome", value=dist_edit)
                contato_edit = st.text_input("Contato", value=dados.iloc[0]["Contato"])
                email_edit = st.text_input("Email", value=dados.iloc[0]["Email"])
                estado_edit = st.selectbox("Estado", sorted(df["Estado"].unique()),
                                          index=sorted(df["Estado"].unique()).index(dados.iloc[0]["Estado"]))
                cidades_disponiveis = [c["nome"] for c in carregar_cidades(estado_edit)]
                cidades_novas = st.multiselect("Cidades", cidades_disponiveis, default=dados["Cidade"].tolist())

                if st.button("Salvar Alterações"):
                    if not validar_telefone(contato_edit.strip()):
                        st.error("Contato inválido!")
                    elif not validar_email(email_edit.strip()):
                        st.error("Email inválido!")
                    else:
                        outras_linhas = df[df["Distribuidor"] != dist_edit]
                        cidades_ocupadas = []
                        for cidade in cidades_novas:
                            if cidade in outras_linhas["Cidade"].tolist() and not (f"{cidade}-{estado_edit}" in set()):
                                dist_existente = outras_linhas.loc[outras_linhas["Cidade"] == cidade, "Distribuidor"].iloc[0]
                                cidades_ocupadas.append(f"{cidade} (atualmente atribuída a {dist_existente})")
                        if cidades_ocupadas:
                            st.error("As seguintes cidades já estão atribuídas a outros distribuidores:\n" + "\n".join(cidades_ocupadas))
                        else:
                            df = df[df["Distribuidor"] != dist_edit]
                            novos = []
                            for cidade in cidades_novas:
                                lat, lon = geocode_city(cidade, estado_edit)
                                lat_v = to_float_safe(lat); lon_v = to_float_safe(lon)
                                if lat_v is not None and lon_v is not None and not latlon_valid(lat_v, lon_v):
                                    lat_v, lon_v = None, None
                                novos.append([nome_edit, contato_edit, email_edit, estado_edit, cidade, lat_v, lon_v])
                            novo_df = pd.DataFrame(novos, columns=COLUNAS)
                            df = pd.concat([df, novo_df], ignore_index=True)
                            salvar_dados_sheet(df)
                            st.success("✅ Alterações salvas!")

        with st.expander("🗑️ Excluir"):
            if not df.empty:
                dist_del = st.selectbox("Distribuidor para excluir", sorted(df["Distribuidor"].unique()))
                if st.button("Excluir Distribuidor"):
                    df = df[df["Distribuidor"] != dist_del]
                    salvar_dados_sheet(df)
                    st.success(f"🗑️ '{dist_del}' removido!")

# MAPA
elif choice == "Mapa":
    st.subheader("🗺️ Mapa de Distribuidores")

    # Sidebar filtros
    st.sidebar.markdown("### 🔎 Filtros do Mapa")

    estados = carregar_estados()
    siglas = [e["sigla"] for e in estados]
    estado_options = [""] + siglas
    estado_index = 0 if st.session_state.estado_filtro == "" else estado_options.index(st.session_state.estado_filtro)
    estado_filtro = st.sidebar.selectbox("Filtrar por Estado", estado_options, index=estado_index)
    st.session_state.estado_filtro = estado_filtro

    # distribuidores opções
    if estado_filtro:
        distribuidores_opcoes = df.loc[df["Estado"] == estado_filtro, "Distribuidor"].dropna().unique().tolist()
    else:
        distribuidores_opcoes = df["Distribuidor"].dropna().unique().tolist()
    distribuidores_opcoes = sorted(distribuidores_opcoes)

    distribuidores_selecionados = st.sidebar.multiselect(
        "Filtrar Distribuidores (opcional)",
        distribuidores_opcoes,
        default=st.session_state.distribuidores_selecionados
    )
    st.session_state.distribuidores_selecionados = [d for d in distribuidores_selecionados if d in distribuidores_opcoes]

    # Busca por cidade (monta lista)
    todas_cidades = []
    try:
        todas_cidades = [f"{c['nome']} - {c['microrregiao']['mesorregiao']['UF']['sigla']}" for e in estados for c in carregar_cidades(e["sigla"])]
    except Exception:
        todas_cidades = sorted(set([f"{row['Cidade']} - {row['Estado']}" for _, row in df.iterrows() if row['Cidade']]))

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
    df_filtro = df.copy()
    if st.session_state.estado_filtro:
        df_filtro = df_filtro[df_filtro["Estado"] == st.session_state.estado_filtro]
    if st.session_state.distribuidores_selecionados:
        df_filtro = df_filtro[df_filtro["Distribuidor"].isin(st.session_state.distribuidores_selecionados)]

    # busca por cidade (prioridade)
    if st.session_state.cidade_busca:
        try:
            cidade_nome, estado_sigla = st.session_state.cidade_busca.split(" - ")
            df_cidade = df[
                (df["Cidade"].str.lower() == cidade_nome.lower()) &
                (df["Estado"].str.upper() == estado_sigla.upper())
            ]
        except Exception:
            df_cidade = pd.DataFrame(columns=COLUNAS)

        if df_cidade.empty:
            st.warning(f"❌ Nenhum distribuidor encontrado em **{st.session_state.cidade_busca}**.")
            # centrar no estado se houver
            zoom_to_state = None
            if st.session_state.estado_filtro:
                df_state = df[df["Estado"] == st.session_state.estado_filtro]
                lats = pd.to_numeric(df_state["Latitude"], errors="coerce").dropna()
                lons = pd.to_numeric(df_state["Longitude"], errors="coerce").dropna()
                lats = lats[(lats >= LAT_MIN) & (lats <= LAT_MAX)]
                lons = lons[(lons >= LON_MIN) & (lons <= LON_MAX)]
                if not lats.empty and not lons.empty:
                    center_lat = float(lats.mean()); center_lon = float(lons.mean())
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
                center_lat = float(lats.mean()); center_lon = float(lons.mean())
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
        # mapa geral
        zoom_to_state = None
        if st.session_state.estado_filtro:
            df_state = df[df["Estado"] == st.session_state.estado_filtro]
            lats = pd.to_numeric(df_state["Latitude"], errors="coerce").dropna()
            lons = pd.to_numeric(df_state["Longitude"], errors="coerce").dropna()
            lats = lats[(lats >= LAT_MIN) & (lats <= LAT_MAX)]
            lons = lons[(lons >= LON_MIN) & (lons <= LON_MAX)]
            if not lats.empty and not lons.empty:
                center_lat = float(lats.mean()); center_lon = float(lons.mean())
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

# FIM
