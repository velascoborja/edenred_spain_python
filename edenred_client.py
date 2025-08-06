#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cliente completo para Edenred España - Obtén saldos, transacciones y datos de cuenta.

USO:
   python edenred_client.py --user <usuario> --password <contraseña> [opciones]

OPCIONES:
   --user          Usuario de Edenred (requerido)
   --password      Contraseña de Edenred (requerido)
   --debug         Mostrar logs detallados del proceso
   --begin-date    Fecha inicio para transacciones (YYYY-MM-DD, por defecto: hace 3 meses)
   --only-balance  Solo mostrar saldos de tarjetas
   --only-transactions  Solo mostrar transacciones
   --card-name     Filtrar transacciones por nombre de tarjeta específica
   --format        Formato de salida: text (por defecto), json, csv
   --output        Archivo de salida (opcional, por defecto: stdout)

EJEMPLOS:
   python edenred_client.py --user mi_usuario --password mi_pass
   python edenred_client.py --user mi_usuario --password mi_pass --only-balance
   python edenred_client.py --user mi_usuario --password mi_pass --begin-date 2025-01-01
   python edenred_client.py --user mi_usuario --password mi_pass --format json --output datos.json

REQUISITOS:
   pip install requests beautifulsoup4
"""
from __future__ import annotations

import argparse
import csv
import getpass
import json
import logging
import re
import sys
import time
from datetime import datetime, timedelta
from html import unescape
from pathlib import Path
from typing import Final, Optional, Dict, Any, List
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup


def get_week_start_date() -> datetime:
    """Obtiene el lunes de la semana actual"""
    today = datetime.now()
    days_since_monday = today.weekday()  # 0 = lunes, 6 = domingo
    monday = today - timedelta(days=days_since_monday)
    return monday.replace(hour=0, minute=0, second=0, microsecond=0)


def calculate_weekly_spending(transactions: List[Dict[str, Any]], weekly_limit: float) -> Dict[str, Any]:
    """Calcula el gasto semanal y el importe restante"""
    week_start = get_week_start_date()
    week_end = week_start + timedelta(days=6, hours=23, minutes=59, seconds=59)
    
    # Filtrar transacciones de esta semana (excluyendo recargas)
    weekly_transactions = []
    weekly_total = 0.0
    
    for trans in transactions:
        # Parsear la fecha de la transacción
        trans_date_str = trans.get('transactionDateWithoutHour', '')
        trans_hour_str = trans.get('transactionHour', '00:00:00')
        
        try:
            trans_datetime = datetime.strptime(f"{trans_date_str} {trans_hour_str}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue  # Si no podemos parsear la fecha, saltar
        
        # Verificar si está en esta semana y no es una recarga
        description = trans.get('transactionDescription', '')
        if (week_start <= trans_datetime <= week_end and 
            'RECARGA' not in description.upper()):
            
            amount = float(trans.get('transactionAmount', 0))
            weekly_transactions.append(trans)
            weekly_total += amount
    
    remaining = weekly_limit - weekly_total
    
    return {
        'week_start': week_start.strftime('%Y-%m-%d'),
        'week_end': week_end.strftime('%Y-%m-%d'),
        'weekly_limit': weekly_limit,
        'weekly_spent': weekly_total,
        'weekly_remaining': remaining,
        'weekly_transactions': weekly_transactions,
        'transactions_count': len(weekly_transactions)
    }


# ────────────────────────── CONSTANTES ──────────────────────────
BASE_PORTAL: Final = "https://clientes.edenred.es"
BASE_EMP: Final = "https://empleados.edenred.es"
BASE_SSO: Final = "https://sso.eu.edenred.io"
BASE_WEBSERVICES: Final = "https://webservices.edenred.es"

HEADERS: Final = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/138.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "es-ES,es;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}

OTP_ENDPOINT = f"{BASE_PORTAL}/ValidacionLogin.aspx/ValidarLoginOtp"
OTP_RETRIES = 3


# ───────────────────────── UTILIDADES ───────────────────────────
def _get_csrf_from_html(html: str) -> str:
    """Extrae el token CSRF del HTML"""
    m = re.search(r'name="__RequestVerificationToken"[^>]+value="([^"]+)"', html)
    if not m:
        raise RuntimeError("No se encontró el token CSRF")
    return unescape(m.group(1))


def _extract_form_data(html: str) -> Dict[str, str]:
    """Extrae todos los campos de un formulario HTML"""
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    if not form:
        return {}
    
    data = {}
    for inp in form.find_all(["input", "select", "textarea"]):
        name = inp.get("name")
        if name:
            if inp.name == "input":
                data[name] = inp.get("value", "")
            elif inp.name == "select":
                selected = inp.find("option", selected=True)
                data[name] = selected.get("value", "") if selected else ""
    
    return data


def _pedir_y_validar_otp(sess: requests.Session, debug: bool) -> None:
    """Maneja el proceso de validación OTP"""
    for intento in range(1, OTP_RETRIES + 1):
        otp = getpass.getpass("Introduce el código OTP de 6 dígitos: ")
        if not re.fullmatch(r"\d{6}", otp):
            print("↪️  Deben ser 6 dígitos.")
            continue

        if debug:
            logging.debug("Enviando OTP %s…", otp)

        r = sess.post(
            OTP_ENDPOINT,
            headers={
                **HEADERS,
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/json; charset=UTF-8",
                "Accept": "*/*",
                "Origin": BASE_PORTAL,
                "Referer": f"{BASE_PORTAL}/ValidacionLogin",
            },
            json={"otp": otp},
        )
        
        if debug:
            logging.debug("POST %s → %s %s", r.request.url, r.status_code, r.reason)
            logging.debug("Respuesta JSON: %s", r.text)

        try:
            response_data = r.json()
            ok = (
                response_data
                .get("d", {})
                .get("meta", {})
                .get("status", "")
                .upper()
                == "SUCCESS"
            )
        except json.JSONDecodeError:
            ok = False

        if ok:
            # El OTP fue aceptado, obtenemos la URL de redirección
            redirect_url = response_data["d"].get("data")
            if redirect_url and debug:
                logging.debug("URL de redirección OTP: %s", redirect_url)
            print("✅ OTP aceptado")
            return redirect_url

        print("❌ OTP incorrecto, vuelve a intentarlo.")
    
    raise RuntimeError("Demasiados intentos fallidos de OTP")


def _handle_callback_form(resp: requests.Response, sess: requests.Session, debug: bool) -> requests.Response:
    """Maneja formularios de callback automáticos del SSO"""
    if "text/html" not in resp.headers.get("Content-Type", ""):
        return resp
    
    html = resp.text
    if '<form' not in html:
        return resp

    # Buscar formularios con campos típicos de OAuth/OpenID Connect
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    if not form:
        return resp

    # Verificar si es un formulario de callback (contiene code, state, etc.)
    inputs = form.find_all("input")
    input_names = [inp.get("name") for inp in inputs if inp.get("name")]
    
    if not any(name in input_names for name in ["code", "state", "id_token"]):
        if debug:
            logging.debug("No es un formulario de callback OAuth, ignorando")
        return resp

    action = form.get("action") or resp.url
    action = urljoin(resp.url, action)
    method = form.get("method", "post").lower()
    
    data = {}
    for inp in inputs:
        name = inp.get("name")
        if name:
            data[name] = inp.get("value", "")

    if debug:
        logging.debug("Auto-enviando formulario callback a %s", action)
        logging.debug("Campos del formulario: %s", list(data.keys()))

    headers = {
        **HEADERS,
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": urlparse(resp.url).scheme + "://" + urlparse(resp.url).netloc,
        "Referer": resp.url,
    }

    if method == "post":
        return sess.post(action, headers=headers, data=data, allow_redirects=True)
    else:
        return sess.get(action, headers=headers, params=data, allow_redirects=True)


def _extract_jwt_token(sess: requests.Session, debug: bool) -> str:
    """Extrae el token JWT de la aplicación de empleados"""
    if debug:
        logging.debug("Intentando obtener token JWT...")
    
    # Primero verificar que estamos en la página correcta
    r = sess.get(f"{BASE_EMP}/", headers=HEADERS, allow_redirects=True)
    if debug:
        logging.debug("GET %s → %s", BASE_EMP, r.status_code)
    
    # Ahora intentar obtener el token
    r = sess.get(
        f"{BASE_EMP}/token",
        headers={
            **HEADERS,
            "Accept": "application/json, text/plain, */*",
            "Referer": f"{BASE_EMP}/",
        },
        allow_redirects=True,
    )
    
    if debug:
        logging.debug("GET /token → %s", r.status_code)
        logging.debug("Response headers: %s", dict(r.headers))
        logging.debug("Response content: %s", r.text[:500])
    
    if r.status_code != 200:
        raise RuntimeError(f"Error al obtener token: HTTP {r.status_code}")
    
    try:
        token_data = r.json()
        
        # Verificar si la respuesta tiene el formato estándar con access_token
        if "access_token" in token_data:
            return token_data["access_token"]
        
        # Verificar si la respuesta tiene el formato de Edenred: {"data": "token", "meta": {...}}
        elif "data" in token_data and "meta" in token_data:
            meta = token_data.get("meta", {})
            if meta.get("status") == "SUCCESS":
                token = token_data.get("data")
                if token:
                    if debug:
                        logging.debug("Token extraído del formato Edenred: %s...", token[:20])
                    return token
                else:
                    raise RuntimeError("El campo 'data' está vacío en la respuesta")
            else:
                messages = meta.get("messages", [])
                error_msg = f"Error del servidor: {messages}" if messages else "Status no es SUCCESS"
                raise RuntimeError(error_msg)
        
        else:
            if debug:
                logging.debug("Token response: %s", token_data)
            raise RuntimeError("La respuesta no contiene access_token ni el formato esperado de Edenred")
            
    except json.JSONDecodeError as e:
        if debug:
            logging.debug("Error parsing JSON: %s", e)
            logging.debug("Response text: %s", r.text)
        raise RuntimeError("No se pudo parsear la respuesta JSON del token")


# ─────────────────────────── LOGIN ──────────────────────────────
def login_and_get_jwt(user: str, password: str, debug: bool) -> str:
    """Realiza el login completo y obtiene el JWT"""
    sess = requests.Session()
    sess.headers.update(HEADERS)
    
    if debug:
        logging.debug("Iniciando proceso de login para usuario: %s", user)

    # 1️⃣ GET inicial a la página de login
    r = sess.get(f"{BASE_PORTAL}/Account/Logon", headers=HEADERS)
    if debug:
        logging.debug("GET /Account/Logon → %s", r.status_code)
    
    csrf = _get_csrf_from_html(r.text)
    if debug:
        logging.debug("CSRF token obtenido: %s...", csrf[:20])

    # 2️⃣ POST con credenciales
    login_data = {
        "__RequestVerificationToken": csrf,
        "UserName": user,
        "Password": password,
        "RememberMe": "false",
    }
    
    login_headers = {
        **HEADERS,
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": BASE_PORTAL,
        "Referer": f"{BASE_PORTAL}/Account/Logon",
    }
    
    r = sess.post(f"{BASE_PORTAL}/Account/Logon", data=login_data, headers=login_headers, allow_redirects=False)
    if debug:
        logging.debug("POST login → %s %s", r.status_code, r.reason)
        if "Location" in r.headers:
            logging.debug("Redirect to: %s", r.headers["Location"])

    # 3️⃣ Seguir redirecciones y manejar OTP si es necesario
    redirect_url = None
    if r.status_code in [302, 303]:
        redirect_url = r.headers.get("Location")
        if redirect_url:
            redirect_url = urljoin(BASE_PORTAL, redirect_url)
            if debug:
                logging.debug("Siguiendo redirección a: %s", redirect_url)
    
    # Si nos redirige a ValidacionLogin, necesitamos OTP
    if redirect_url and "/ValidacionLogin" in redirect_url:
        if debug:
            logging.debug("Se requiere validación OTP")
        
        # Visitar la página de validación OTP
        r = sess.get(redirect_url, headers=HEADERS)
        if debug:
            logging.debug("GET ValidacionLogin → %s", r.status_code)
        
        # Procesar OTP
        otp_redirect = _pedir_y_validar_otp(sess, debug)
        
        # Si el OTP devuelve una URL de redirección, seguirla
        if otp_redirect:
            r = sess.get(otp_redirect, headers=HEADERS, allow_redirects=True)
            if debug:
                logging.debug("Siguiendo redirección post-OTP: %s → %s", otp_redirect, r.status_code)
    
    elif redirect_url:
        # Seguir la redirección normal
        r = sess.get(redirect_url, headers=HEADERS, allow_redirects=True)
        if debug:
            logging.debug("Siguiendo redirección: %s → %s", redirect_url, r.status_code)

    # 4️⃣ Manejar posibles formularios de callback del SSO
    max_redirects = 5
    redirect_count = 0
    
    while redirect_count < max_redirects:
        # Verificar si estamos en una página de SSO que requiere auto-submit
        current_domain = urlparse(r.url).netloc
        if debug:
            logging.debug("Current URL: %s (domain: %s)", r.url, current_domain)
        
        if current_domain == "sso.eu.edenred.io" or "callback" in r.url.lower():
            if debug:
                logging.debug("Detectada página SSO/callback, verificando formularios...")
            
            new_resp = _handle_callback_form(r, sess, debug)
            if new_resp.url != r.url:  # Si cambió la URL, hubo redirección
                r = new_resp
                redirect_count += 1
                continue
        
        # Si llegamos a empleados.edenred.es, intentar obtener el token
        if current_domain == "empleados.edenred.es":
            if debug:
                logging.debug("Llegamos a empleados.edenred.es, intentando obtener JWT...")
            break
        
        # Si hay redirecciones automáticas, seguirlas
        if r.status_code in [301, 302, 303, 307, 308] and "Location" in r.headers:
            new_url = urljoin(r.url, r.headers["Location"])
            if debug:
                logging.debug("Redirección automática a: %s", new_url)
            r = sess.get(new_url, headers=HEADERS, allow_redirects=True)
            redirect_count += 1
        else:
            break
    
    # 5️⃣ Extraer el JWT token
    try:
        jwt_token = _extract_jwt_token(sess, debug)
        if debug:
            logging.debug("JWT token obtenido exitosamente")
        return jwt_token
    except Exception as e:
        if debug:
            logging.debug("Error obteniendo JWT: %s", e)
            logging.debug("URL final: %s", r.url)
            logging.debug("Status code final: %s", r.status_code)
        raise RuntimeError(f"No se pudo obtener el token JWT: {e}")


def get_user_data(jwt_token: str, debug: bool) -> Dict[str, Any]:
    """Obtiene datos del usuario usando el JWT token"""
    headers = {
        **HEADERS,
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Origin": BASE_EMP,
        "Referer": f"{BASE_EMP}/",
    }
    
    r = requests.get(f"{BASE_WEBSERVICES}/gateway-app/Identity/UserData", headers=headers)
    if debug:
        logging.debug("GET UserData → %s", r.status_code)
    
    if r.status_code != 200:
        raise RuntimeError(f"Error obteniendo datos de usuario: HTTP {r.status_code}")
    
    return r.json()


def get_products_and_cards(jwt_token: str, debug: bool) -> Dict[str, Any]:
    """Obtiene productos y tarjetas del usuario"""
    headers = {
        **HEADERS,
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Origin": BASE_EMP,
        "Referer": f"{BASE_EMP}/",
    }
    
    r = requests.get(f"{BASE_WEBSERVICES}/gateway-app/User/EmployeeProductsAndCards", headers=headers)
    if debug:
        logging.debug("GET EmployeeProductsAndCards → %s", r.status_code)
        logging.debug("Response content: %s", r.text[:1000])
    
    if r.status_code != 200:
        raise RuntimeError(f"Error obteniendo productos y tarjetas: HTTP {r.status_code}")
    
    return r.json()


def get_transactions(jwt_token: str, card_guid: str, begin_date: str = None, debug: bool = False) -> Dict[str, Any]:
    """Obtiene las transacciones de una tarjeta específica"""
    if not begin_date:
        # Por defecto, últimos 3 meses
        from datetime import datetime, timedelta
        begin_date = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d")
    
    params = {
        "numberOfRecordsPerPage": "50",  # Aumentamos para obtener más transacciones
        "pageNumber": "0",
        "cardGuid": card_guid,
        "beginDate": begin_date,
    }
    
    headers = {
        **HEADERS,
        "Authorization": f"Bearer {jwt_token}",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "Origin": BASE_EMP,
        "Referer": f"{BASE_EMP}/",
    }
    
    r = requests.get(f"{BASE_WEBSERVICES}/gateway-app/User/EmployeeTransactionSearch", 
                     headers=headers, params=params)
    if debug:
        logging.debug("GET EmployeeTransactionSearch → %s", r.status_code)
        logging.debug("URL: %s", r.url)
    
    if r.status_code != 200:
        raise RuntimeError(f"Error obteniendo transacciones: HTTP {r.status_code}")
    
    return r.json()


def get_all_transactions_for_card(jwt_token: str, card_guid: str, begin_date: str = None, debug: bool = False) -> List[Dict[str, Any]]:
    """Obtiene TODAS las transacciones de una tarjeta con paginación automática"""
    if not begin_date:
        begin_date = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d")
    
    all_transactions = []
    page_number = 0
    records_per_page = 100  # Máximo permitido
    
    while True:
        params = {
            "numberOfRecordsPerPage": str(records_per_page),
            "pageNumber": str(page_number),
            "cardGuid": card_guid,
            "beginDate": begin_date,
        }
        
        headers = {
            **HEADERS,
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": BASE_EMP,
            "Referer": f"{BASE_EMP}/",
        }
        
        r = requests.get(f"{BASE_WEBSERVICES}/gateway-app/User/EmployeeTransactionSearch", 
                         headers=headers, params=params)
        
        if debug:
            logging.debug("GET EmployeeTransactionSearch página %d → %s", page_number, r.status_code)
            if page_number == 0:  # Solo mostrar el contenido de la primera página para no saturar los logs
                logging.debug("Response content primera página: %s", r.text[:2000])
        
        if r.status_code != 200:
            if page_number == 0:  # Error en la primera página
                raise RuntimeError(f"Error obteniendo transacciones: HTTP {r.status_code}")
            else:  # Error en páginas siguientes, romper el bucle
                break
        
        data = r.json()
        if 'data' in data and 'rows' in data['data']:
            transactions = data['data']['rows']
            if not transactions:  # No hay más transacciones
                break
            all_transactions.extend(transactions)
            page_number += 1
            
            # Si obtenemos menos transacciones que el máximo, es la última página
            if len(transactions) < records_per_page:
                break
        else:
            break
    
    return all_transactions


def export_to_csv(data: Dict[str, Any], output_file: str) -> None:
    """Exporta los datos a formato CSV"""
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        # Escribir información del usuario
        csvfile.write(f"# Usuario: {data.get('user_name', 'N/A')}\n")
        csvfile.write(f"# Fecha de exportación: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        csvfile.write("\n")
        
        # Escribir saldos de tarjetas
        csvfile.write("# SALDOS DE TARJETAS\n")
        writer = csv.writer(csvfile)
        writer.writerow(["Tarjeta", "Saldo (€)", "GUID"])
        
        for card in data.get('cards', []):
            writer.writerow([
                card.get('cardName', 'N/A'),
                card.get('balance', 'N/A'),
                card.get('cardGuid', 'N/A')
            ])
        
        csvfile.write("\n# TRANSACCIONES\n")
        writer.writerow(["Tarjeta", "Fecha", "Importe (€)", "Descripción", "Tipo", "Referencia"])
        
        # Escribir todas las transacciones
        for card_name, transactions in data.get('transactions', {}).items():
            for trans in transactions:
                writer.writerow([
                    card_name,
                    f"{trans.get('transactionDateWithoutHour', 'N/A')} {trans.get('transactionHour', '')}".strip(),
                    trans.get('transactionAmount', 'N/A'),
                    trans.get('transactionDescription', 'N/A'),
                    'RECARGA' if 'RECARGA' in trans.get('transactionDescription', '').upper() else 'GASTO',
                    trans.get('transactionExternalReference', 'N/A')
                ])


def format_transaction_text(trans: Dict[str, Any]) -> str:
    """Formatea una transacción para mostrar en texto"""
    date = trans.get('transactionDateWithoutHour', 'N/A')
    hour = trans.get('transactionHour', '')
    amount = trans.get('transactionAmount', 'N/A')
    description = trans.get('transactionDescription', 'N/A')
    
    # Formatear la fecha completa
    datetime_str = f"{date} {hour}" if hour else date
    
    # Formatear la línea con emojis según el tipo
    emoji = "💰" if "RECARGA" in description.upper() else "🛒"
    
    return f"  {emoji} {datetime_str} - {amount}€ en {description}"


def print_weekly_summary(weekly_data: Dict[str, Any]) -> None:
    """Imprime un resumen del gasto semanal"""
    print("\n" + "="*60)
    print("📅 RESUMEN SEMANAL - TICKET RESTAURANT")
    print("="*60)
    
    print(f"📆 Semana actual: {weekly_data['week_start']} al {weekly_data['week_end']}")
    print(f"💳 Tarjeta: {weekly_data.get('card_name', 'N/A')}")
    print(f"🎯 Límite semanal: {weekly_data['weekly_limit']:.2f}€")
    print(f"💸 Gastado esta semana: {weekly_data['weekly_spent']:.2f}€")
    
    remaining = weekly_data['weekly_remaining']
    if remaining > 0:
        print(f"✅ Disponible restante: {remaining:.2f}€")
        percentage_used = (weekly_data['weekly_spent'] / weekly_data['weekly_limit']) * 100
        print(f"📊 Porcentaje usado: {percentage_used:.1f}%")
    elif remaining == 0:
        print("⚠️  Límite semanal alcanzado exactamente")
    else:
        print(f"❌ Límite semanal excedido en: {abs(remaining):.2f}€")
    
    print(f"🧾 Transacciones esta semana: {weekly_data['transactions_count']}")
    
    if weekly_data['weekly_transactions']:
        print("\n📝 Transacciones de esta semana:")
        for trans in weekly_data['weekly_transactions']:
            date = trans.get('transactionDateWithoutHour', 'N/A')
            hour = trans.get('transactionHour', '')
            amount = trans.get('transactionAmount', 'N/A')
            description = trans.get('transactionDescription', 'N/A')
            datetime_str = f"{date} {hour}" if hour else date
            print(f"  🛒 {datetime_str} - {amount}€ en {description}")
    
    print("="*60)


def print_summary(data: Dict[str, Any]) -> None:
    """Imprime un resumen bonito de los datos"""
    print("\n" + "="*60)
    print("📊 RESUMEN DE CUENTA EDENRED")
    print("="*60)
    
    # Información del usuario
    user_name = data.get('user_name', 'N/A')
    print(f"👤 Usuario: {user_name}")
    
    # Saldos totales
    cards = data.get('cards', [])
    total_balance = sum(float(card.get('balance', 0)) for card in cards if card.get('balance') != 'N/A')
    print(f"💳 Total tarjetas: {len(cards)}")
    print(f"💰 Saldo total: {total_balance:.2f}€")
    
    # Transacciones totales
    all_transactions = []
    for transactions in data.get('transactions', {}).values():
        all_transactions.extend(transactions)
    
    if all_transactions:
        total_spent = sum(float(t.get('transactionAmount', 0)) for t in all_transactions 
                         if t.get('transactionAmount') != 'N/A' and float(t.get('transactionAmount', 0)) > 0 
                         and 'RECARGA' not in t.get('transactionDescription', '').upper())
        total_loaded = sum(float(t.get('transactionAmount', 0)) for t in all_transactions 
                          if t.get('transactionAmount') != 'N/A' and 'RECARGA' in t.get('transactionDescription', '').upper())
        
        print(f"📈 Transacciones encontradas: {len(all_transactions)}")
        print(f"💸 Total gastado: {total_spent:.2f}€")
        print(f"💵 Total cargado: {total_loaded:.2f}€")
    
    print("="*60)


# ──────────────────────────── MAIN ──────────────────────────────
def collect_all_data(user: str, password: str, begin_date: str = None, card_filter: str = None, weekly_limit: float = None, debug: bool = False) -> Dict[str, Any]:
    """Recopila todos los datos de la cuenta Edenred"""
    print("🔐 Iniciando proceso de autenticación...")
    jwt_token = login_and_get_jwt(user, password, debug)
    print("✅ Autenticación exitosa")
    
    print("\n👤 Obteniendo datos del usuario...")
    user_data = get_user_data(jwt_token, debug)
    user_name = f"{user_data.get('firstName', '')} {user_data.get('lastName', '')}".strip()
    
    print("\n💳 Obteniendo información de tarjetas...")
    products = get_products_and_cards(jwt_token, debug)
    
    if debug:
        logging.debug("Estructura completa de productos: %s", json.dumps(products, indent=2))
    
    cards = []
    # La estructura correcta es: products['data'] es una lista de productos,
    # cada producto tiene cardsInfo[] con las tarjetas
    if 'data' in products and isinstance(products['data'], list):
        for product in products['data']:
            product_name = product.get('productName', 'Producto desconocido')
            cards_info = product.get('cardsInfo', [])
            
            for card_info in cards_info:
                # Omitir tarjetas desactivadas (cardStatus = 3)
                card_status = card_info.get('cardStatus')
                if card_status == 3:
                    if debug:
                        logging.debug("Omitiendo tarjeta desactivada: %s (status: %d)", 
                                    card_info.get('cardMaskedPanNumber', 'N/A'), card_status)
                    continue
                
                # Crear un objeto tarjeta con la información necesaria
                card = {
                    'cardName': product_name,  # Usar el nombre del producto como nombre de tarjeta
                    'cardGuid': card_info.get('id'),  # El GUID está en 'id'
                    'balance': card_info.get('balance', 0),
                    'cardNumber': card_info.get('cardMaskedPanNumber', 'N/A'),
                    'cardStatus': card_status,
                    'isPlasticless': card_info.get('isPlasticless', False),
                    'productId': product.get('productId'),
                    'accountNumber': card_info.get('accountNumber')
                }
                cards.append(card)
    
    if debug:
        logging.debug("Tarjetas procesadas: %d", len(cards))
        if cards:
            logging.debug("Primera tarjeta procesada: %s", json.dumps(cards[0], indent=2))
    
    if not cards:
        raise RuntimeError("❌ No se encontraron tarjetas en la cuenta")
    
    # Filtrar tarjetas si se especificó un filtro
    if card_filter:
        filtered_cards = [card for card in cards if card_filter.lower() in card.get('cardName', '').lower()]
        if not filtered_cards:
            available_cards = [card.get('cardName', 'Sin nombre') for card in cards]
            raise RuntimeError(f"❌ No se encontró tarjeta con nombre '{card_filter}'. Disponibles: {', '.join(available_cards)}")
        cards = filtered_cards
    
    print(f"Encontradas {len(cards)} tarjeta(s):")
    for i, card in enumerate(cards):
        balance = card.get('balance', 'N/A')
        print(f"  {i+1}. {card.get('cardName', 'Sin nombre')} - Saldo: {balance}€")
    
    # Recopilar transacciones
    all_transactions = {}
    weekly_summary = None
    
    # Para cálculo semanal, necesitamos transacciones desde el lunes de esta semana
    if weekly_limit:
        week_start = get_week_start_date()
        effective_begin_date = week_start.strftime('%Y-%m-%d')
        print(f"\n📅 Calculando gasto semanal desde {effective_begin_date} (límite: {weekly_limit}€)")
    else:
        effective_begin_date = begin_date
        print("\n💰 Obteniendo transacciones...")
    
    for card in cards:
        card_guid = card.get('cardGuid')
        card_name = card.get('cardName', 'Sin nombre')
        
        if not card_guid:
            continue
            
        print(f"📊 Procesando {card_name}...")
        try:
            transactions = get_all_transactions_for_card(jwt_token, card_guid, effective_begin_date, debug)
            all_transactions[card_name] = transactions
            print(f"   → {len(transactions)} transacciones obtenidas")
            
            # Si se especificó límite semanal, calcular el resumen
            if weekly_limit and transactions:
                weekly_summary = calculate_weekly_spending(transactions, weekly_limit)
                weekly_summary['card_name'] = card_name
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
            all_transactions[card_name] = []
    
    result = {
        'user_name': user_name,
        'cards': cards,
        'transactions': all_transactions,
        'export_date': datetime.now().isoformat(),
        'begin_date': effective_begin_date
    }
    
    if weekly_summary:
        result['weekly_summary'] = weekly_summary
    
    return result


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Cliente completo para Edenred España",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EJEMPLOS:
  %(prog)s --user mi_usuario --password mi_pass
  %(prog)s --user mi_usuario --password mi_pass --only-balance
  %(prog)s --user mi_usuario --password mi_pass --begin-date 2025-01-01
  %(prog)s --user mi_usuario --password mi_pass --format json --output datos.json
  %(prog)s --user mi_usuario --password mi_pass --card-name "Ticket Restaurant"
  %(prog)s --user mi_usuario --password mi_pass --weekly-limit 55.0
        """
    )
    
    # Argumentos requeridos
    ap.add_argument("--user", required=True, help="Usuario Edenred")
    ap.add_argument("--password", required=True, help="Contraseña Edenred")
    
    # Opciones de filtrado
    ap.add_argument("--begin-date", help="Fecha inicio transacciones (YYYY-MM-DD). Por defecto: hace 3 meses")
    ap.add_argument("--card-name", help="Filtrar por nombre de tarjeta específica")
    ap.add_argument("--weekly-limit", type=float, help="Límite semanal en euros (ej: 55.0). Calcula el importe restante para la semana actual")
    
    # Opciones de funcionamiento
    ap.add_argument("--only-balance", action="store_true", help="Solo mostrar saldos de tarjetas")
    ap.add_argument("--only-transactions", action="store_true", help="Solo mostrar transacciones")
    ap.add_argument("--debug", action="store_true", help="Mostrar logs detallados")
    
    # Opciones de salida
    ap.add_argument("--format", choices=["text", "json", "csv"], default="text", 
                   help="Formato de salida (por defecto: text)")
    ap.add_argument("--output", help="Archivo de salida (por defecto: stdout)")
    
    args = ap.parse_args()

    # Configurar logging
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s: %(message)s")
        logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    else:
        # Solo mostrar errores críticos
        logging.basicConfig(level=logging.ERROR)

    try:
        # Recopilar todos los datos
        data = collect_all_data(
            user=args.user,
            password=args.password,
            begin_date=args.begin_date,
            card_filter=args.card_name,
            weekly_limit=args.weekly_limit,
            debug=args.debug
        )
        
        print("\n✅ Datos recopilados exitosamente")
        
        # Procesar salida según el formato solicitado
        if args.format == "json":
            output_data = json.dumps(data, indent=2, ensure_ascii=False)
            
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(output_data)
                print(f"📁 Datos exportados a {args.output}")
            else:
                print("\n" + output_data)
        
        elif args.format == "csv":
            if not args.output:
                args.output = f"edenred_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            
            export_to_csv(data, args.output)
            print(f"📁 Datos exportados a {args.output}")
        
        else:  # formato text
            if args.output:
                # Redirigir stdout a archivo
                original_stdout = sys.stdout
                with open(args.output, 'w', encoding='utf-8') as f:
                    sys.stdout = f
                    show_text_output(data, args)
                sys.stdout = original_stdout
                print(f"📁 Datos exportados a {args.output}")
            else:
                show_text_output(data, args)
                
    except KeyboardInterrupt:
        print("\n\n⏹️  Proceso interrumpido por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Error: {e}", file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def show_text_output(data: Dict[str, Any], args) -> None:
    """Muestra la salida en formato texto"""
    
    # Si hay resumen semanal, mostrarlo primero
    if 'weekly_summary' in data:
        print_weekly_summary(data['weekly_summary'])
        
        # Si solo se pidió el resumen semanal, no mostrar más información
        if args.weekly_limit and not args.only_balance and not args.only_transactions:
            return
    
    # Mostrar resumen siempre (a menos que sea solo transacciones)
    if not args.only_transactions:
        print_summary(data)
    
    # Mostrar saldos si se solicitó
    if not args.only_transactions:
        print("\n💳 SALDOS DE TARJETAS:")
        print("-" * 40)
        cards = data.get('cards', [])
        for i, card in enumerate(cards, 1):
            card_name = card.get('cardName', 'Sin nombre')
            balance = card.get('balance', 'N/A')
            print(f"{i:2d}. {card_name:<25} {balance:>10}€")
    
    # Mostrar transacciones si se solicitó
    if not args.only_balance:
        print("\n📊 TRANSACCIONES:")
        print("-" * 60)
        
        transactions_data = data.get('transactions', {})
        if not transactions_data:
            print("❌ No se encontraron transacciones")
        else:
            for card_name, transactions in transactions_data.items():
                if not transactions:
                    continue
                    
                print(f"\n🏷️  {card_name} ({len(transactions)} transacciones):")
                
                # Ordenar transacciones por fecha (más recientes primero)
                sorted_transactions = sorted(
                    transactions, 
                    key=lambda x: f"{x.get('transactionDateWithoutHour', '')} {x.get('transactionHour', '')}", 
                    reverse=True
                )
                
                # Mostrar hasta 20 transacciones más recientes
                display_count = min(20, len(sorted_transactions))
                for trans in sorted_transactions[:display_count]:
                    print(format_transaction_text(trans))
                
                if len(sorted_transactions) > display_count:
                    remaining = len(sorted_transactions) - display_count
                    print(f"  📝 ... y {remaining} transacciones más (usa --format json para ver todas)")


if __name__ == "__main__":
    main()
