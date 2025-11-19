import streamlit as st
import pandas as pd
import folium
from streamlit_folium import st_folium
from geopy.geocoders import Nominatim
import requests

DATA_FILE = "distribuidores.csv"

# -----------------------------
# Funções IBGE
# -----------------------------
@st.cache_data
def carregar_estados():
    url = "https://servicodados.ibge.gov.br/api/v1/localidades/estados"
    resp = requests.get(url)
    return sorted(resp.json(), key=lambda e: e['nome'])

@st.cache_data
def carregar_cidades(uf):
    url = f"https://servicodados.ibge.gov.br/api/v1/localidades/estados/{uf}/municipios"
    resp = requests.get(url)
    return sorted(resp.json(), key=lambda c: c['nome'])


# 🔥 NOVO: buscar população IBGE
@st.cache_data
def obter_populacao(cidade, estado_sigla):
    try:
        # lista cidades do estado
        url = f"https://servicodados.ibge.gov.br/api/v1/localidades/estados/{estado_sigla}/municipios"
        resp = requests.get(url, timeout=5)
        if resp.status_code != 200:
            return None

        cidades = resp.json()
        c_info = next((c for c in cidades if c["nome"].lower() == cidade.lower()), None)
        if not c_info:
            return None

        cidade_id = c_info["id"]

        # busca população
        pop_url = f"https://servicodados.ibge.gov.br/api/v1/projecoes/populacao/{cidade_id}"
        pop_resp = requests.get(pop_url, timeout=5)
        if pop_resp.status_code != 200:
            return None

        pop_json = pop_resp.json()
        return pop_json.get("projecao", {}).get("populacao")

    except:
        return None


# -----------------------------
# Carregar CSV
# -----------------------------
def carregar_dados():
    try:
        df = pd.read_csv(DATA_FILE)
        for col in ["Distribuidor", "Contato", "Estado", "Cidade", "Latitude", "Longitude"]:
            if col not in df.columns:
                df[col] = ""
        df = df.dropna(subset=["Distribuidor", "Contato", "Estado", "Cidade"], how='all')
        return df[["Distribuidor", "Contato", "Estado", "Cidade", "Latitude", "Longitude"]]
    except FileNotFoundError:
        df = pd.DataFrame(columns=["Distribuidor", "Contato", "Estado", "Cidade", "Latitude", "Longitude"])
        df.to_csv(DATA_FILE, index=False)
        return df

# -----------------------------
# Inicializar session_state
# -----------------------------
if "df" not in st.session_state:
    st.session_state.df = carregar_dados()

# -----------------------------
# Cor fixa por distribuidor
# -----------------------------
def cor_distribuidor(nome):
    h = abs(hash(nome)) % 0xFFFFFF
    return f"#{h:06X}"

# -----------------------------
# Criar mapa
# -----------------------------
def criar_mapa(df):
    df_valid = df[(df["Latitude"].notna()) & (df["Longitude"].notna()) & (df["Latitude"] != "") & (df["Longitude"] != "")]
    if df_valid.empty:
        return folium.Map(location=[-14.2350, -51.9253], zoom_start=4)

    lats = df_valid["Latitude"].astype(float).tolist()
    lons = df_valid["Longitude"].astype(float).tolist()
    centro = [sum(lats)/len(lats), sum(lons)/len(lons)]
    mapa = folium.Map(location=centro, zoom_start=4)

    for _, row in df_valid.iterrows():
        lat = float(row["Latitude"])
        lon = float(row["Longitude"])
        cidade = row["Cidade"]
        estado = row["Estado"]

        # população
        pop = obter_populacao(cidade, estado) or "Não disponível"

        # tooltip final
        tooltip_text = f"{row['Distribuidor']} ({cidade} - {estado}) - População: {pop}"

        folium.CircleMarker(
            location=[lat, lon],
            radius=6,
            color=cor_distribuidor(row["Distribuidor"]),
            fill=True,
            fill_color=cor_distribuidor(row["Distribuidor"]),
            popup=tooltip_text
        ).add_to(mapa)

    mapa.fit_bounds([[min(lats), min(lons)], [max(lats), max(lons)]])
    return mapa

# -----------------------------
# Atualiza mapa
# -----------------------------
def atualizar_mapa():
    mapa = criar_mapa(st.session_state.df)
    st_folium(mapa, width=700, height=500)

# -----------------------------
# Streamlit UI
# -----------------------------
st.title("Sistema de Distribuidores Seguro")
tab1, tab2, tab3 = st.tabs(["Cadastro", "Lista / Editar", "Mapa"])

# Aba 1 etc...
