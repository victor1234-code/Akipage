import streamlit as st
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
import os
import pickle
import requests
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Configuración de credenciales de OAuth
CLIENT_ID = "YOUR_CLIENT_ID"  # Reemplaza con tu CLIENT_ID de Google Cloud Console
CLIENT_SECRET = "YOUR_CLIENT_SECRET"  # Reemplaza con tu CLIENT_SECRET de Google Cloud Console
REDIRECT_URI = "http://localhost:8501"  # Para desarrollo local, cambia en producción

# Si no tienes un archivo de token guardado, esta será la ruta de almacenamiento
TOKEN_PICKLE = "token.pickle"


# Función para guardar el token de acceso
def save_token(credentials):
    with open(TOKEN_PICKLE, 'wb') as token:
        pickle.dump(credentials, token)


# Función para cargar el token de acceso guardado
def load_token():
    if os.path.exists(TOKEN_PICKLE):
        with open(TOKEN_PICKLE, 'rb') as token:
            return pickle.load(token)
    return None


# Iniciar el flujo de autenticación OAuth
def start_oauth_flow():
    flow = Flow.from_client_config(
        {
            "installed": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [REDIRECT_URI],
            }
        },
        scopes=["profile", "email"]
    )
    flow.redirect_uri = REDIRECT_URI
    auth_url, _ = flow.authorization_url(access_type='offline', prompt='consent')
    return auth_url, flow


# Obtener datos del perfil del usuario de la API de Google
def get_user_info(credentials):
    try:
        service = build("oauth2", "v2", credentials=credentials)
        user_info = service.userinfo().get().execute()
        return user_info
    except HttpError as err:
        st.error(f"Error al obtener información del usuario: {err}")
        return None


# Iniciar Streamlit
def main():
    st.title("Autenticación con Google OAuth 2.0")

    # Si ya hay un token guardado, lo cargamos
    credentials = load_token()

    if credentials and credentials.valid:
        # Si las credenciales son válidas, obtenemos el perfil del usuario
        user_info = get_user_info(credentials)
        if user_info:
            st.write(f"Nombre: {user_info['name']}")
            st.write(f"Correo electrónico: {user_info['email']}")
        else:
            st.write("No se pudo obtener la información del usuario.")
    else:
        # Si no tenemos un token válido, iniciamos el flujo OAuth
        auth_url, flow = start_oauth_flow()
        st.markdown(f"Por favor, [inicia sesión con Google aquí]({auth_url})")
        
        # Después de que el usuario haga login, Google redirige a este script
        if 'code' in st.experimental_get_query_params():
            code = st.experimental_get_query_params()['code'][0]
            flow.fetch_token(authorization_response=f"{REDIRECT_URI}?code={code}")
            credentials = flow.credentials
            save_token(credentials)
            st.success("Autenticación exitosa!")
            st.experimental_rerun()


if __name__ == "__main__":
    main()
