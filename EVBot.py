# -*- coding: utf-8 -*-

from config import *
#pip install pyTelegramBotAPI
#pip install pycryptodome
import base64
import calendar
import copy
import hashlib
import json
import logging
import math
import os
import re
import shutil
import threading
import time
import unicodedata
import requests
import telebot
from telebot.types import (
    ReplyKeyboardMarkup,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    KeyboardButton,
    BotCommand,
)
import datetime

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- Utilidades de cifrado/descifrado 100% compatibles con CryptoJS.AES.encrypt/decrypt(texto, password),
# tal y como lo usa el dashboard ev_manager.html (antes vivían en crypto_utils.py; se integran aquí
# para que EVBot.py sea un único fichero autocontenido y no dependa de otro módulo externo). ---
_SALT_PREFIX = b"Salted__"
_KEY_LEN = 32  # AES-256
_IV_LEN = 16


class CryptoJSError(Exception):
    """Se lanza cuando el texto no se puede descifrar (contraseña incorrecta o dato corrupto)."""


def _evp_bytes_to_key(password: bytes, salt: bytes, key_len: int, iv_len: int):
    """Replica OpenSSL EVP_BytesToKey con MD5, que es lo que usa CryptoJS por defecto."""
    derived = b""
    block = b""
    while len(derived) < key_len + iv_len:
        block = hashlib.md5(block + password + salt).digest()
        derived += block
    return derived[:key_len], derived[key_len:key_len + iv_len]


def encrypt_cryptojs(plaintext: str, password: str) -> str:
    """Cifra un texto igual que CryptoJS.AES.encrypt(plaintext, password).toString()."""
    salt = os.urandom(8)
    key, iv = _evp_bytes_to_key(password.encode("utf-8"), salt, _KEY_LEN, _IV_LEN)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    raw = _SALT_PREFIX + salt + ciphertext
    return base64.b64encode(raw).decode("utf-8")


def decrypt_cryptojs(ciphertext_b64: str, password: str) -> str:
    """Descifra un texto generado por CryptoJS.AES.encrypt(). Lanza CryptoJSError si falla."""
    try:
        raw = base64.b64decode(ciphertext_b64, validate=True)
    except Exception as exc:
        raise CryptoJSError("El contenido cifrado no es válido.") from exc

    if len(raw) < 16 or not raw.startswith(_SALT_PREFIX):
        raise CryptoJSError("El contenido cifrado no tiene el formato esperado.")

    salt = raw[8:16]
    ciphertext = raw[16:]
    key, iv = _evp_bytes_to_key(password.encode("utf-8"), salt, _KEY_LEN, _IV_LEN)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        padded = cipher.decrypt(ciphertext)
        plaintext_bytes = unpad(padded, AES.block_size)
        return plaintext_bytes.decode("utf-8")
    except (ValueError, KeyError, UnicodeDecodeError) as exc:
        raise CryptoJSError("Contraseña incorrecta.") from exc


logging.basicConfig(
	level=logging.INFO,
	format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("EVBot")

bot = telebot.TeleBot(TELEGRAM_TOKEN)
PRECIO_KWH_CASA=0.18
PORCENTAJE_BASE = 2.0
KWH_BASE = 1.0
datos = {}

# Segundos de espera antes de reintentar si Telegram no es accesible al arrancar.
REINTENTO_CONEXION_SEGUNDOS = 15


def _ocultar_token(valor):
    """Devuelve el texto de un error con el token del bot censurado.

    Los errores de `requests` incluyen la URL completa de la API, que lleva el token dentro
    (`https://api.telegram.org/bot<TOKEN>/getUpdates...`). Sin esto, un simple fallo de red
    escribe el token en la consola y en cualquier fichero de log, que es justo lo que no
    queremos: quien lea ese log puede controlar el bot entero."""
    texto = str(valor)
    if TELEGRAM_TOKEN:
        texto = texto.replace(TELEGRAM_TOKEN, "<TOKEN OCULTO>")
        # El token también aparece a veces sin el prefijo "bot" o partido por el ':'.
        sufijo = TELEGRAM_TOKEN.split(":", 1)[-1]
        if len(sufijo) > 8:
            texto = texto.replace(sufijo, "<TOKEN OCULTO>")
    return texto


_registrar_next_step_original = bot.register_next_step_handler


def _registrar_next_step_con_actividad(message, callback, *args, **kwargs):
    """Envoltorio de bot.register_next_step_handler que además refresca la marca de tiempo
    (_ts) de la sesión, si ya tiene contraseña guardada. Así, el purgador de sesiones
    abandonadas (_purgar_sesiones_caducadas, más abajo) solo borra conversaciones realmente
    inactivas y no interrumpe a un usuario que sigue respondiendo preguntas del asistente,
    aunque tarde varios minutos entre una y otra."""
    estado = datos.get(message.chat.id)
    if estado is not None and "password" in estado:
        estado["_ts"] = datetime.datetime.now()
    return _registrar_next_step_original(message, callback, *args, **kwargs)


bot.register_next_step_handler = _registrar_next_step_con_actividad

# --- Configuración del backup compartido con el dashboard (ev_manager.html) ---
# Si tu config.py define EV_BACKUP_PATH / EV_BACKUP_PASSWORD se usan esos valores.
try:
    EV_BACKUP_PATH
except NameError:
    EV_BACKUP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ev_backup.json")

try:
    EV_BACKUP_PASSWORD
except NameError:
    EV_BACKUP_PASSWORD = None  # Si se define aquí, el bot no preguntará contraseña cada vez.

# --- Control de acceso: solo estos chat_id de Telegram podrán usar el bot. ---
# Defínelo en config.py como: ALLOWED_USER_IDS = [123456789, 987654321]
# Si se deja vacío, CUALQUIER usuario que encuentre el bot podrá usarlo (no recomendado).
try:
    ALLOWED_USER_IDS
except NameError:
    ALLOWED_USER_IDS = []

if not ALLOWED_USER_IDS:
    logger.warning("ALLOWED_USER_IDS no está configurado en config.py: cualquier usuario podrá usar este bot.")


def usuario_autorizado(chat_id):
    if not ALLOWED_USER_IDS:
        return True
    return chat_id in ALLOWED_USER_IDS


# --- Avisos entre usuarios ---
# Cuando alguien anota una carga o una lectura OBD, el resto se entera al momento en vez de
# tener que consultarlo en el bot.
#
# Por defecto se avisa a todos los de ALLOWED_USER_IDS menos a quien lo ha anotado (cada uno
# lo recibe en SU chat privado con el bot).
#
# Si prefieres que además (o en vez de eso) llegue a vuestro grupo de Telegram, define en
# config.py:  EV_AVISOS_CHAT_IDS = [-1001234567890]
# El id de un grupo es NEGATIVO y para poder escribir ahí el bot tiene que estar añadido al
# grupo. Para conservar solo el aviso de grupo, pon también:  EV_AVISOS_SOLO_EXTRA = True
try:
    EV_AVISOS_CHAT_IDS
except NameError:
    EV_AVISOS_CHAT_IDS = []

try:
    EV_AVISOS_SOLO_EXTRA
except NameError:
    EV_AVISOS_SOLO_EXTRA = False

# --- Aviso diario proactivo (mantenimiento que vence y luz barata) ---
# Es lo único que el bot puede hacer y la extensión no: el mensaje llega solo,
# sin abrir nada. Para desactivarlo, pon en config.py:  EV_AVISOS_HORA = None
try:
    EV_AVISOS_HORA
except NameError:
    EV_AVISOS_HORA = 9        # hora local a la que se manda el aviso (0-23)

try:
    EV_AVISOS_DIAS
except NameError:
    EV_AVISOS_DIAS = 15       # avisar cuando falten estos días o menos

try:
    EV_AVISOS_KM
except NameError:
    EV_AVISOS_KM = 500        # o cuando falten estos km o menos

# Nombre de cada usuario, cacheado: se pregunta a Telegram una sola vez por chat.
_nombres_chat = {}


# --- Copias de seguridad automáticas del backup, antes de cada escritura ---
EV_BACKUP_BACKUPS_DIR = os.path.join(os.path.dirname(os.path.abspath(EV_BACKUP_PATH)), "backups")
EV_BACKUP_MAX_BACKUPS = 10


class _BloqueoArchivo:
    """Bloqueo simple basado en un archivo .lock, para evitar que el bot y el dashboard web
    (u otro proceso) escriban/lean el backup al mismo tiempo y lo corrompan."""

    def __init__(self, path, timeout=5, espera=0.1):
        self.lock_path = path + ".lock"
        self.timeout = timeout
        self.espera = espera
        self._fd = None

    def __enter__(self):
        inicio = time.time()
        while True:
            try:
                self._fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                return self
            except FileExistsError:
                if time.time() - inicio > self.timeout:
                    # Lock probablemente abandonado por un proceso que murió: lo liberamos
                    # para no dejar el bot bloqueado indefinidamente.
                    try:
                        os.remove(self.lock_path)
                    except OSError:
                        pass
                    continue
                time.sleep(self.espera)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
        try:
            os.remove(self.lock_path)
        except OSError:
            pass


def _rotar_backup():
    """Guarda una copia del backup actual antes de sobrescribirlo, y limpia las más antiguas."""
    if not os.path.exists(EV_BACKUP_PATH):
        return
    try:
        os.makedirs(EV_BACKUP_BACKUPS_DIR, exist_ok=True)
        marca = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        destino = os.path.join(EV_BACKUP_BACKUPS_DIR, f"ev_backup_{marca}.json")
        shutil.copy2(EV_BACKUP_PATH, destino)
        copias = sorted(f for f in os.listdir(EV_BACKUP_BACKUPS_DIR) if f.startswith("ev_backup_"))
        for vieja in copias[:-EV_BACKUP_MAX_BACKUPS]:
            try:
                os.remove(os.path.join(EV_BACKUP_BACKUPS_DIR, vieja))
            except OSError:
                pass
    except Exception:
        logger.exception("No se pudo rotar la copia de seguridad del backup (se continúa igualmente)")


def _escribir_archivo_crudo(contenido):
    """Escribe el contenido tal cual en el archivo de backup, con bloqueo, copia previa y de forma atómica."""
    with _BloqueoArchivo(EV_BACKUP_PATH):
        _rotar_backup()
        tmp_path = EV_BACKUP_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(contenido, f, ensure_ascii=False)
        os.replace(tmp_path, EV_BACKUP_PATH)


# Misma estructura por defecto que la extensión (shared/model.js) y ev_manager.html
DEFAULT_APP_DATA = {
    "settings": {
        "model": "Opel Mokka-e", "capacity": 46, "wltp": 332, "efficiency": 80,
        "priceEV": 32000, "priceICE": 22000, "iceLiters": 5.8, "icePrice": 1.50,
        "pDay": 0.22, "pNight": 0.03, "homePower": 4.4,
        # Tarifa eléctrica: mismas claves que la extensión, para que los dos
        # lados calculen exactamente el mismo coste de recarga.
        "tarifaModo": "tramos",     # "tramos" | "dos" | "fijo" | "pvpc"
        "tarifaP1": 0.22, "tarifaP2": 0.13, "tarifaP3": 0.03,
        "tarifaHoraPunta": 8, "tarifaHoraValle": 22,
        "tarifaFijo": 0.15, "costeFijoMes": 0,
        "city": "", "ciudad": "", "provincia": "",
    },
    "logs": [],
    "obd": [],
    "gastos": [],
    # Lápidas de borrado: sin esto, lo que borras en la extensión reaparece
    # aquí en cuanto el bot reescribe el backup.
    "borrados": [],
    "meta": {},
}

# Un borrado se recuerda medio año; pasado ese plazo la lápida ya no aporta y
# solo engorda el archivo.
DIAS_LAPIDA = 180


def _leer_archivo_backup():
    if not os.path.exists(EV_BACKUP_PATH):
        return None
    with _BloqueoArchivo(EV_BACKUP_PATH):
        with open(EV_BACKUP_PATH, "r", encoding="utf-8") as f:
            return json.load(f)


def cargar_datos(password=None):
    """Devuelve (appData, es_archivo_nuevo). Lanza CryptoJSError si la contraseña no es correcta."""
    crudo = _leer_archivo_backup()
    if crudo is None:
        return copy.deepcopy(DEFAULT_APP_DATA), True
    if crudo.get("isEncrypted"):
        if not password:
            raise CryptoJSError("El archivo está cifrado y no se indicó contraseña.")
        texto = decrypt_cryptojs(crudo["content"], password)
        return _normalizar_datos(json.loads(texto)), False
    return _normalizar_datos(crudo), False


def _normalizar_datos(app_data):
    """Rellena lo que falte en backups de versiones anteriores, sin tocar lo que ya haya.

    No se borra nada: si el archivo trae claves que este bot no conoce (por
    ejemplo las que solo usa la extensión) se guardan tal cual al reescribirlo."""
    if not isinstance(app_data, dict):
        return app_data
    settings = app_data.setdefault("settings", {})
    for lista in ("logs", "obd", "gastos"):
        app_data.setdefault(lista, [])
    app_data.setdefault("meta", {})

    # Se descartan las lápidas caducadas y se aplican las vigentes: un registro
    # borrado en cualquier equipo no debe seguir vivo en este archivo.
    if isinstance(app_data.get("borrados"), list):
        limite = (time.time() - DIAS_LAPIDA * 86400) * 1000
        lapidas = [b for b in app_data["borrados"]
                   if isinstance(b, dict)
                   and b.get("col") in ("logs", "obd", "gastos")
                   and b.get("id")
                   and _num(b.get("ts"), 0) > limite]
        app_data["borrados"] = lapidas
        for col in ("logs", "obd", "gastos"):
            fuera = {str(b["id"]) for b in lapidas if b["col"] == col}
            if fuera:
                app_data[col] = [r for r in app_data[col]
                                 if not isinstance(r, dict) or str(r.get("id")) not in fuera]
    else:
        app_data["borrados"] = []
    # Antes solo existían pDay/pNight (día y noche). Se convierten en la tarifa
    # por tramos para que el bot y la extensión calculen lo mismo.
    settings.setdefault("tarifaModo", "tramos")
    settings.setdefault("tarifaP1", _num(settings.get("pDay"), 0.22))
    settings.setdefault("tarifaP3", _num(settings.get("pNight"), 0.03))
    # El llano no existía: se estima entre punta y valle mientras no se configure.
    settings.setdefault("tarifaP2", round((settings["tarifaP1"] + settings["tarifaP3"]) / 2, 3))
    settings.setdefault("tarifaHoraPunta", 8)
    settings.setdefault("tarifaHoraValle", 22)
    settings.setdefault("tarifaFijo", settings["tarifaP1"])
    settings.setdefault("costeFijoMes", 0)
    # El bot llamaba "city" a lo que la extensión llama "ciudad".
    ciudad = settings.get("ciudad") or settings.get("city") or ""
    settings["ciudad"] = ciudad
    settings["city"] = ciudad
    return app_data


def marcar_borrado(app_data, col, registro_id):
    """Deja constancia de un borrado para que la extensión no lo resucite."""
    if col not in ("logs", "obd", "gastos") or not registro_id:
        return app_data
    ident = str(registro_id)
    app_data.setdefault("borrados", [])
    app_data["borrados"] = [b for b in app_data["borrados"]
                            if not (b.get("col") == col and str(b.get("id")) == ident)]
    app_data["borrados"].append({"col": col, "id": ident, "ts": int(time.time() * 1000)})
    return app_data


def guardar_datos(app_data, password=None):
    """Escribe el backup de forma atómica, cifrado con AES (compatible con CryptoJS) si hay contraseña."""
    # La marca de tiempo decide quién gana al fusionar: sin ella, la extensión
    # creería que lo escrito por el bot es siempre más viejo.
    if isinstance(app_data, dict):
        app_data["meta"] = {"actualizado": int(time.time() * 1000), "dispositivo": "evbot"}
    texto = json.dumps(app_data, ensure_ascii=False)
    if password:
        contenido = {"isEncrypted": True, "content": encrypt_cryptojs(texto, password)}
    else:
        contenido = app_data
    _escribir_archivo_crudo(contenido)


# =========================================================================
# Fecha/hora de las cargas.
# La fecha/hora de inicio y fin de una carga NUNCA se debe asumir automáticamente como "ahora":
# se puede anotar una carga antes de que empiece, o completar los datos que faltan mucho después
# de que la carga haya terminado, y el momento en que se escribe en el bot no tiene por qué
# coincidir con el momento real en que la carga empezó o terminó. Por eso se pregunta siempre de
# forma explícita. Se escribe a mano ("ahora", "ayer 22:00", "4/8 20:30"...) porque un calendario
# de botones obligaba a demasiados toques para algo que se anota a diario.
# =========================================================================

DTPICKER_PREGUNTAS = {
    "H_INI": "¿Cuándo enchufaste el coche?",
    "H_FIN": "¿Cuándo terminó la carga?",
    "H_FIN_NUEVA": "¿Cuándo terminó la carga?",
    "S_INI": "¿Cuándo empezaste a cargar?",
    "S_FIN": "¿Cuándo terminaste de cargar?",
    "OBD": "¿Qué día hiciste la lectura OBD?",
    "GASTO": "¿Qué día fue el gasto?",
}

# Contextos que solo necesitan un DÍA (sin hora): el registro OBD y los gastos,
# igual que sus campos <input type="date"> en la extensión, no guardan hora.
CTX_SOLO_FECHA = {"OBD", "GASTO"}

# Contextos en los que la fecha se puede dejar SIN RELLENAR. Enchufas el coche a
# media tarde y lo apuntas en ese momento: todavía no sabes a qué hora terminará.
# Preferimos guardar la carga sin fin (y editarla luego) a obligar a inventarse
# una hora que acabaría en el histórico como si fuera real.
CTX_FECHA_OPCIONAL = {"H_FIN", "H_FIN_NUEVA"}

# Lo que se acepta como "no lo sé" en esos contextos.
RESPUESTAS_SIN_FECHA = {"-", "no", "no lo se", "no se", "ni idea", "todavia no",
                        "aun no", "luego", "despues", "mas tarde", "saltar", "vacio"}

# Mismos tipos y mismas claves que TIPOS_GASTO en shared/model.js: si aquí se
# usara otra clave, la extensión mostraría el gasto como "Otros".
TIPOS_GASTO = {
    "mantenimiento": "Mantenimiento",
    "itv": "ITV",
    "seguro": "Seguro",
    "impuesto": "Impuesto de circulación",
    "neumaticos": "Neumáticos",
    "reparacion": "Reparación",
    "accesorio": "Accesorios",
    "peaje": "Peajes y parking",
    "luzFija": "Cuota fija de la luz",
    "otro": "Otros",
}

# Mismo límite que LIMITE_TEXTO en shared/model.js.
LIMITE_TEXTO_GASTO = 60


def _num(valor, por_defecto=0.0):
    """Número tolerante: acepta None, cadenas con coma decimal y basura."""
    if valor is None or valor == "":
        return por_defecto
    try:
        return float(str(valor).replace(",", "."))
    except (TypeError, ValueError):
        return por_defecto


def _parse_iso(iso):
    """'YYYY-MM-DDTHH:MM' o 'YYYY-MM-DD' -> datetime, o None si no se entiende."""
    if not iso:
        return None
    texto = str(iso)
    for formato in ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(texto[:len("2000-01-01T00:00:00")], formato)
        except ValueError:
            continue
    return None


def _formatear_fecha_hora(iso):
    """'YYYY-MM-DDTHH:MM' -> 'DD/MM/YYYY HH:MM', para mostrar al usuario."""
    if not iso:
        return "sin definir"
    try:
        dt = datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M")
        return dt.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return iso


def _formatear_fecha_solo(iso):
    """'YYYY-MM-DD' -> 'DD/MM/YYYY', para mostrar al usuario."""
    if not iso:
        return "sin definir"
    try:
        dt = datetime.datetime.strptime(iso, "%Y-%m-%d")
        return dt.strftime("%d/%m/%Y")
    except Exception:
        return iso


def _fecha_corta(iso):
    """Fecha compacta 'DD/MM/YYYY' para los listados, aceptando tanto el formato de las cargas
    ('YYYY-MM-DDTHH:MM', con hora) como el de los registros OBD ('YYYY-MM-DD', sin hora).
    En un listado la hora exacta no aporta y sí hace que la línea no quepa en el móvil."""
    if not iso:
        return "sin fecha"
    texto = str(iso).split("T")[0]
    try:
        return datetime.datetime.strptime(texto, "%Y-%m-%d").strftime("%d/%m/%Y")
    except Exception:
        return texto


# --- Introducir fecha y hora ---
# Telegram no ofrece un selector de fecha nativo para bots: o se escribe, o se construye un
# calendario a base de botones. El calendario obligaba a demasiados toques (mes, día, y luego
# la hora a saltos de 5/30/60 min), así que se pide escrita. A cambio, el bot tiene que ser
# flexible interpretando lo que se escribe, que es de lo que se encarga _parsear_fecha_hora.
_RE_HORA = re.compile(r"^(\d{1,2})[:.h](\d{2})$")
_RE_FECHA = re.compile(r"^(\d{1,2})[/-](\d{1,2})(?:[/-](\d{2,4}))?$")
_RE_HACE = re.compile(r"^hace\s+(\d+)\s*(m|min|mins|minuto|minutos|h|hora|horas)$")

_DIAS_RELATIVOS = {"hoy": 0, "ayer": 1, "anteayer": 2}


def _parsear_fecha_hora(texto, solo_fecha=False, ahora=None):
    """Interpreta una fecha/hora escrita a mano. Devuelve un datetime, o None si no la entiende.

    Acepta: 'ahora', 'hace 2h', 'hace 30 min', 'hoy', 'ayer', 'anteayer', '20:30',
    'ayer 22:00', '4/8 20:30', '04/08/2026 20:30' (y con guiones o '20.30' / '20h30').

    Devolver None en vez de adivinar es deliberado: es preferible volver a preguntar que
    guardar una fecha inventada en el histórico."""
    ahora = (ahora or datetime.datetime.now()).replace(second=0, microsecond=0)
    t = " ".join(_normalizar_texto(texto).lower().split())
    if not t:
        return None

    if t in ("ahora", "ya", "ahora mismo"):
        return ahora

    m = _RE_HACE.match(t)
    if m:
        cantidad = int(m.group(1))
        unidad = m.group(2)
        delta = datetime.timedelta(hours=cantidad) if unidad.startswith("h") else datetime.timedelta(minutes=cantidad)
        return ahora - delta

    partes = t.split()
    primero = partes[0]
    fecha_base = None
    resto = list(partes)

    if primero in _DIAS_RELATIVOS:
        fecha_base = (ahora - datetime.timedelta(days=_DIAS_RELATIVOS[primero])).date()
        resto = resto[1:]
    else:
        m = _RE_FECHA.match(primero)
        if m:
            dia, mes = int(m.group(1)), int(m.group(2))
            anio_txt = m.group(3)
            anio = ahora.year if anio_txt is None else int(anio_txt)
            if anio < 100:
                anio += 2000
            try:
                fecha_base = datetime.date(anio, mes, dia)
            except ValueError:
                return None
            # Sin año explícito y en el futuro: se está anotando algo que ya ha pasado, así que
            # un "31/12" escrito en enero es del año anterior, no del que viene.
            if anio_txt is None and fecha_base > ahora.date() + datetime.timedelta(days=1):
                try:
                    fecha_base = fecha_base.replace(year=anio - 1)
                except ValueError:
                    return None
            resto = resto[1:]

    hora = None
    if resto:
        if len(resto) > 1:
            return None
        m = _RE_HORA.match(resto[0])
        if not m:
            return None
        h, mi = int(m.group(1)), int(m.group(2))
        if h > 23 or mi > 59:
            return None
        hora = datetime.time(h, mi)

    if fecha_base is None and hora is None:
        return None

    if fecha_base is None:
        # Solo hora: se asume hoy, salvo que quede en el futuro. Quien anota una carga a las
        # 8:00 escribiendo "22:30" se refiere a anoche, no a esta noche.
        candidato = datetime.datetime.combine(ahora.date(), hora)
        if candidato > ahora + datetime.timedelta(minutes=5):
            candidato -= datetime.timedelta(days=1)
        return candidato

    if hora is None:
        if solo_fecha:
            return datetime.datetime.combine(fecha_base, datetime.time(0, 0))
        if primero in _DIAS_RELATIVOS:
            return datetime.datetime.combine(fecha_base, ahora.time())
        return None  # una fecha suelta no basta donde hace falta la hora

    return datetime.datetime.combine(fecha_base, hora)


def _dtpicker_texto(ctx, valor_inicial_iso=None):
    if ctx.startswith("EDITLOG_"):
        campo = ctx[len("EDITLOG_"):]
        etiqueta_campo = {"date": "INICIO", "dateEnd": "FIN"}.get(campo, campo)
        pregunta = f"Nueva fecha/hora de {etiqueta_campo}:"
    else:
        pregunta = DTPICKER_PREGUNTAS.get(ctx.replace("_EDIT", ""), "¿Cuándo?")

    if ctx in CTX_SOLO_FECHA:
        texto = (
            f"📅 {pregunta}\n\n"
            "Escríbelo como quieras:\n"
            "• `hoy`\n"
            "• `ayer`\n"
            "• `4/8`\n"
            "• `04/08/2026`"
        )
    else:
        texto = (
            f"📅 {pregunta}\n\n"
            "Escríbelo como quieras:\n"
            "• `ahora`\n"
            "• `20:30`  (de hoy)\n"
            "• `ayer 22:00`\n"
            "• `hace 2h`\n"
            "• `4/8 20:30`"
        )
    if ctx in CTX_FECHA_OPCIONAL:
        texto += "\n\n🤷 Si aún no lo sabes, escribe `-` y lo dejamos vacío: podrás añadirlo luego."
    if valor_inicial_iso:
        actual = _formatear_fecha_solo(valor_inicial_iso) if ctx in CTX_SOLO_FECHA else _formatear_fecha_hora(valor_inicial_iso)
        texto += f"\n\nAhora mismo tiene: *{actual}*"
    return texto


def iniciar_selector_fecha_hora(chat_id, ctx, valor_inicial_iso=None):
    """Pide la fecha (y hora, salvo en los contextos de CTX_SOLO_FECHA) escribiéndola."""
    datos.setdefault(chat_id, {})["_dtctx"] = ctx
    if ctx in CTX_FECHA_OPCIONAL:
        pista = "Ej: 23:30, o - si no lo sabes"
    elif ctx in CTX_SOLO_FECHA:
        pista = "Ej: 4/8"
    else:
        pista = "Ej: ayer 22:00"
    msg = bot.send_message(
        chat_id,
        _dtpicker_texto(ctx, valor_inicial_iso),
        reply_markup=teclado_cancelar(pista),
        parse_mode="Markdown",
    )
    bot.register_next_step_handler(msg, _recibir_fecha_escrita)


def _recibir_fecha_escrita(message):
    if es_cancelacion(message):
        return
    chat_id = message.chat.id
    ctx = datos.get(chat_id, {}).get("_dtctx")
    if not ctx:
        mostrar_menu(chat_id, "Se ha perdido el hilo de la conversación. Empieza otra vez desde el menú.")
        return

    if ctx in CTX_FECHA_OPCIONAL and _normalizar_texto(message.text).lower().strip() in RESPUESTAS_SIN_FECHA:
        datos.get(chat_id, {}).pop("_dtctx", None)
        bot.send_message(chat_id, "👍 Lo dejamos vacío. Podrás añadirlo cuando lo sepas.")
        _confirmar_seleccion_fecha(chat_id, message, ctx, None)
        return

    solo_fecha = ctx in CTX_SOLO_FECHA
    dt = _parsear_fecha_hora(message.text, solo_fecha=solo_fecha)
    if dt is None:
        ejemplo = "`4/8` o `ayer`" if solo_fecha else "`ayer 22:00`, `20:30` o `hace 2h`"
        if ctx in CTX_FECHA_OPCIONAL:
            ejemplo += " (o `-` si aún no lo sabes)"
        msg = bot.send_message(
            chat_id,
            f"🙈 No he entendido esa fecha.\n\nPrueba con {ejemplo}.",
            reply_markup=teclado_cancelar("Ej: 4/8" if solo_fecha else "Ej: ayer 22:00"),
            parse_mode="Markdown",
        )
        bot.register_next_step_handler(msg, _recibir_fecha_escrita)
        return

    datos.get(chat_id, {}).pop("_dtctx", None)
    if solo_fecha:
        iso = dt.strftime("%Y-%m-%d")
        bot.send_message(chat_id, f"✅ Fecha: {_formatear_fecha_solo(iso)}")
    else:
        iso = dt.strftime("%Y-%m-%dT%H:%M")
        bot.send_message(chat_id, f"✅ Fecha y hora: {_formatear_fecha_hora(iso)}")
    _confirmar_seleccion_fecha(chat_id, message, ctx, iso)


def _confirmar_seleccion_fecha(chat_id, message, ctx, iso):
    """Guarda la fecha ya interpretada en el sitio que corresponda y sigue con el flujo que la
    había pedido. `message` es el mensaje del usuario, que las pantallas siguientes usan solo
    para sacar el chat_id."""
    if ctx == "H_INI":
        nueva = datos.setdefault(chat_id, {}).setdefault("nuevaCarga", {})
        nueva["fechaInicio"] = iso
        msg = bot.send_message(
            chat_id,
            "🔋 ¿Con qué % de batería has enchufado el coche?\n\nEjemplo: 35",
            reply_markup=teclado_cancelar("Solo el número, ej: 35"),
        )
        bot.register_next_step_handler(msg, recibir_percent_inicial_casa)
    elif ctx == "H_INI_EDIT":
        nueva = datos.setdefault(chat_id, {}).setdefault("nuevaCarga", {})
        nueva["fechaInicio"] = iso
        mostrar_confirmacion_carga_casa(message)
    elif ctx == "S_INI":
        nueva = datos.setdefault(chat_id, {}).setdefault("nuevaCarga", {})
        nueva["fechaInicio"] = iso
        msg = bot.send_message(chat_id, "🔋 ¿Cuántos kWh has cargado?\n\nEjemplo: 25.5", reply_markup=teclado_cancelar("Solo el número, ej: 25.5"))
        bot.register_next_step_handler(msg, recibir_kwh_carga)
    elif ctx == "S_INI_EDIT":
        nueva = datos.setdefault(chat_id, {}).setdefault("nuevaCarga", {})
        nueva["fechaInicio"] = iso
        mostrar_confirmacion_carga(message)
    elif ctx == "S_FIN":
        nueva = datos.setdefault(chat_id, {}).setdefault("nuevaCarga", {})
        nueva["fechaFin"] = iso
        mostrar_menu_avanzado_street(message)
    elif ctx == "S_FIN_EDIT":
        nueva = datos.setdefault(chat_id, {}).setdefault("nuevaCarga", {})
        nueva["fechaFin"] = iso
        mostrar_confirmacion_carga(message)
    elif ctx == "H_FIN":
        _completar_carga_pendiente(chat_id, iso)
    elif ctx == "H_FIN_NUEVA":
        nueva = datos.setdefault(chat_id, {}).setdefault("nuevaCarga", {})
        if iso:
            nueva["fechaFin"] = iso
            preguntar_percent_final_casa(chat_id)
        else:
            nueva.pop("fechaFin", None)
            nueva.pop("socEnd", None)
            mostrar_menu_avanzado_home(message)
    elif ctx == "OBD":
        nuevo = datos.setdefault(chat_id, {}).setdefault("nuevoObd", {})
        nuevo["fecha"] = iso
        preguntar_soh_obd(message)
    elif ctx == "GASTO":
        nuevo = datos.setdefault(chat_id, {}).setdefault("nuevoGasto", {})
        nuevo["fecha"] = iso
        preguntar_tipo_gasto(chat_id)
    elif ctx.startswith("EDITLOG_"):
        key = ctx[len("EDITLOG_"):]
        datos.setdefault(chat_id, {}).setdefault("editLog", {}).setdefault("overrides", {})[key] = iso
        mostrar_menu_editar_log(chat_id)


def _capacidad_efectiva(app_data):
    """Capacidad útil de la batería (kWh) hoy, según el último SoH conocido.

    Traducción literal de `capacidadEfectiva()` en shared/autonomia.js. Si el
    OBD da la capacidad medida se usa esa: es un dato real, mejor que aplicarle
    un porcentaje a la nominal del folleto."""
    return _capacidad_detallada(app_data)[0]


def _capacidad_detallada(app_data):
    """(capacidad, soh, fuente). `fuente` es 'nominal', 'OBD' o 'SoH'."""
    settings = app_data.get("settings", {}) or {}
    nominal = _num(settings.get("capacity"), 46) or 46
    obd = [o for o in (app_data.get("obd") or []) if _num(o.get("soh")) > 0]
    if not obd:
        return nominal, 100.0, "nominal"
    ultimo = sorted(obd, key=lambda o: str(o.get("date") or ""))[-1]
    soh = _num(ultimo.get("soh"), 100)
    if _num(ultimo.get("cap")) > 0:
        return _num(ultimo.get("cap")), soh, "OBD"
    return nominal * soh / 100, soh, "SoH"


# ---------------------------------------------------------------------------
#  AUTONOMÍA REAL Y TIEMPOS DE CARGA
#  Traducción literal de evmanager-extension/shared/autonomia.js. Igual que con
#  la tarifa, los dos lados tienen que dar el mismo número: lo verifica
#  evmanager-extension/build/comparar_autonomia.py.
# ---------------------------------------------------------------------------
def _clamp(valor, minimo, maximo):
    return max(minimo, min(maximo, valor))


def _consumo_real(app_data, n=20):
    """Consumo medio real (kWh/100 km) de las últimas `n` cargas con datos.

    Devuelve None si no hay histórico suficiente: es preferible decir "no lo sé"
    a inventarse un consumo con una sola carga."""
    utiles = [l for l in (app_data.get("logs") or [])
              if _num(l.get("kwh")) > 0 and _num(l.get("km")) > 0]
    utiles.sort(key=lambda l: str(l.get("date") or ""))
    utiles = utiles[-n:]
    if len(utiles) < 2:
        return None
    kwh = sum(_num(l.get("kwh")) for l in utiles)
    km = sum(_num(l.get("km")) for l in utiles)
    if km <= 0:
        return None
    return {"consumo": (kwh / km) * 100, "muestras": len(utiles), "km": km}


def _factor_temperatura(t):
    """Cuánto más gasta el coche a `t` grados frente a los 20 °C de referencia."""
    if t is None:
        return 1.0
    try:
        t = float(t)
    except (TypeError, ValueError):
        return 1.0
    if t < 20:
        return _clamp(1 + (20 - t) * 0.012, 1.0, 1.6)
    if t > 25:
        return _clamp(1 + (t - 25) * 0.008, 1.0, 1.25)
    return 1.0


def _tasa_carga(soc):
    """Curva de aceptación en C (veces la capacidad por hora), no en kW, para
    que valga con cualquier batería. Casi llena admite muchísima menos."""
    if soc < 30:
        return 1.96
    if soc < 55:
        return 1.5
    if soc < 75:
        return 1.04
    if soc < 80:
        return 0.7
    if soc < 90:
        return 0.34
    return 0.16


def _rendimiento_carga(potencia):
    """La energía del contador NO es la que entra en la batería: entre un 6 % y
    un 17 % se va en el cargador de a bordo, el cable y la climatización de la
    batería. Cuanto más lenta la carga, peor rendimiento."""
    p = _num(potencia)
    if p <= 2.4:
        return 0.83     # enchufe doméstico
    if p <= 7.4:
        return 0.88     # wallbox monofásica
    if p <= 22:
        return 0.90     # wallbox trifásica
    return 0.94         # carga rápida en continua


def _minutos_carga(capacidad, desde, hasta, potencia, rendimiento=None, penalizacion=1.0):
    """Minutos para pasar de `desde` % a `hasta` %, con pérdidas y, por encima
    de 11 kW, con la curva de carga."""
    cap = _num(capacidad)
    kw = _num(potencia)
    ini = _clamp(_num(desde), 0, 100)
    fin = _clamp(_num(hasta), 0, 100)
    if cap <= 0 or kw <= 0 or fin <= ini:
        return 0.0
    entregada = kw * (rendimiento if rendimiento is not None else _rendimiento_carga(kw)) * penalizacion
    minutos = 0.0
    for i in range(int(math.floor(ini)), int(math.ceil(fin))):
        limite = min(entregada, _tasa_carga(i) * cap) if kw > 11 else entregada
        minutos += ((cap * 0.01) / max(limite, 0.1)) * 60
    return minutos


def _autonomia_real(app_data, soc=100, temp=None, reserva=5):
    """Kilómetros que quedan de verdad. `reserva` es el % que no piensas gastar."""
    capacidad, soh, fuente = _capacidad_detallada(app_data)
    settings = app_data.get("settings", {}) or {}
    real = _consumo_real(app_data)
    if real:
        base = real["consumo"]
    else:
        wltp = max(_num(settings.get("wltp"), 1), 1)
        base = (_num(settings.get("capacity")) / wltp) * 100
    if not base or not capacidad:
        return None
    factor = _factor_temperatura(temp)
    consumo = base * factor
    disponible = capacidad * _clamp(soc - reserva, 0, 100) / 100
    return {
        "km": (disponible / consumo) * 100,
        "consumo": consumo, "consumo_base": base, "factor": factor,
        "capacidad": capacidad, "soh": soh, "estimado": real is None,
        "fuente_capacidad": fuente, "kwh_disponibles": disponible,
    }


def _formatear_duracion(minutos):
    """'8 h 53 min' / '45 min'. Redondea al minuto: dar segundos sería fingir
    una precisión que este cálculo no tiene."""
    total = int(round(_num(minutos)))
    if total < 60:
        return f"{total} min"
    return f"{total // 60} h {total % 60:02d} min"


# ---------------------------------------------------------------------------
#  TARIFA ELÉCTRICA DE CASA
#  Traducción literal de evmanager-extension/shared/tarifa.js. Los dos lados
#  tienen que dar el mismo euro para la misma carga, así que si se cambia uno
#  hay que cambiar el otro.
#
#  Periodos 2.0TD (península y Baleares):
#    P1 Punta  10-14 y 18-22        (laborables)
#    P2 Llano   8-10, 14-18 y 22-24 (laborables)
#    P3 Valle   0-8 laborables + todo el sábado, domingo y festivo nacional
# ---------------------------------------------------------------------------
ETIQUETA_PERIODO = {"P1": "punta ☀️", "P2": "llano 🌤️", "P3": "valle 🌙"}
MODOS_TRAMOS = ("tramos", "dos")


def _domingo_de_pascua(anio):
    """Algoritmo de Meeus/Jones/Butcher. Sirve para situar el Viernes Santo."""
    a, b, c = anio % 19, anio // 100, anio % 100
    d, e, f = b // 4, b % 4, (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = c // 4, c % 4
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    mes = (h + l - 7 * m + 114) // 31
    dia = ((h + l - 7 * m + 114) % 31) + 1
    return datetime.date(anio, mes, dia)


def _es_festivo_nacional(fecha):
    """Festivos de toda España. Los autonómicos y locales no se contemplan: como
    mucho se cobraría P1 un día que era P3, nunca al revés."""
    fijos = {(1, 1), (1, 6), (5, 1), (8, 15), (10, 12), (11, 1), (12, 6), (12, 8), (12, 25)}
    if (fecha.month, fecha.day) in fijos:
        return True
    viernes_santo = _domingo_de_pascua(fecha.year) - datetime.timedelta(days=2)
    return (fecha.month, fecha.day) == (viernes_santo.month, viernes_santo.day)


def _periodo_2_0td(fecha):
    """Periodo 'P1' | 'P2' | 'P3' de un instante, con los horarios de la 2.0TD."""
    if fecha.weekday() >= 5 or _es_festivo_nacional(fecha):
        return "P3"
    h = fecha.hour
    if h < 8:
        return "P3"
    if (10 <= h < 14) or (18 <= h < 22):
        return "P1"
    return "P2"


def _periodo_dos_tramos(settings, fecha):
    """Tarifa de dos precios: punta de `tarifaHoraPunta` a `tarifaHoraValle` en
    días laborables; el resto (noches, fines de semana y festivos), valle."""
    if fecha.weekday() >= 5 or _es_festivo_nacional(fecha):
        return "P3"
    ini = min(max(int(round(_num(settings.get("tarifaHoraPunta"), 8))), 0), 23)
    fin = min(max(int(round(_num(settings.get("tarifaHoraValle"), 22))), 0), 24)
    h = fecha.hour
    # Si la punta cruza la medianoche (raro, pero posible) se invierte la comparación.
    en_punta = (ini <= h < fin) if ini < fin else (h >= ini or h < fin)
    return "P1" if en_punta else "P3"


def _periodo_segun_modo(settings, fecha):
    """Periodo del instante según el modo configurado, o None si no hay tramos."""
    modo = settings.get("tarifaModo") or "tramos"
    if modo == "dos":
        return _periodo_dos_tramos(settings, fecha)
    if modo == "tramos":
        return _periodo_2_0td(fecha)
    return None


# ---------------------------------------------------------------------------
#  PVPC REAL (Red Eléctrica)
#  Traducción de evmanager-extension/shared/energy.js. Sin esto, el modo 'pvpc'
#  se caía a los tramos EN SILENCIO y cada carga anotada por Telegram quedaba
#  guardada con un precio inventado.
# ---------------------------------------------------------------------------
URL_ESIOS = "https://api.esios.ree.es/archives/70/download_json"
URL_APIDATOS = "https://apidatos.ree.es/es/datos/mercados/precios-mercados-tiempo-real"
ESPERA_PVPC = 12
_cache_pvpc = {}
_lock_pvpc = threading.Lock()


def _num_es(valor):
    """'203,53' -> 203.53. REE devuelve los precios con coma decimal."""
    try:
        return float(str(valor).replace(" ", "").replace(",", "."))
    except (TypeError, ValueError):
        return float("nan")


def _parsear_esios(json_datos, zona):
    filas = json_datos.get("PVPC") if isinstance(json_datos, dict) else None
    if not isinstance(filas, list):
        raise ValueError("formato ESIOS inesperado")
    horas = []
    for fila in filas:
        try:
            h = int(str(fila.get("Hora", ""))[:2])
        except (TypeError, ValueError):
            continue
        precio = _num_es(fila.get(zona, fila.get("PCB")))
        # €/MWh -> €/kWh
        precio = precio / 1000 if precio == precio else precio
        if 0 <= h <= 24 and precio == precio and 0 <= precio < 10:
            horas.append({"h": h, "precio": precio})
    if not horas:
        raise ValueError("ESIOS sin datos")
    return horas


def _parsear_apidatos(json_datos):
    bloques = json_datos.get("included") if isinstance(json_datos, dict) else None
    if not isinstance(bloques, list) or not bloques:
        raise ValueError("formato apidatos inesperado")
    bloque = next((b for b in bloques if "pvpc" in str(b.get("type", "")).lower()), bloques[0])
    valores = (bloque.get("attributes") or {}).get("values")
    if not isinstance(valores, list):
        raise ValueError("formato apidatos inesperado")
    horas = []
    for v in valores:
        fecha = _parse_iso(str(v.get("datetime", ""))[:16])
        precio = _num_es(v.get("value")) / 1000
        if fecha and precio == precio and 0 <= precio < 10:
            horas.append({"h": fecha.hour, "precio": precio})
    if not horas:
        raise ValueError("apidatos sin datos")
    return horas


def _obtener_precios_pvpc(fecha_iso=None, zona=None):
    """Precios hora a hora de un día. Devuelve {'horas': [...], 'fuente': ...} o None.

    Se cachea en memoria porque el PVPC de un día no cambia una vez publicado.
    Los fallos también se cachean 15 minutos: si REE está caída, no tiene
    sentido reintentar en cada carga que anote el usuario."""
    fecha_iso = fecha_iso or datetime.date.today().isoformat()
    zona = zona or "PCB"
    clave = (fecha_iso, zona)
    with _lock_pvpc:
        guardado = _cache_pvpc.get(clave)
        if guardado and (guardado.get("horas") or time.time() - guardado.get("ts", 0) < 900):
            return guardado if guardado.get("horas") else None

    horas, fuente = None, "pvpc"
    try:
        res = requests.get(URL_ESIOS, params={"locale": "es", "date": fecha_iso}, timeout=ESPERA_PVPC)
        res.raise_for_status()
        horas = _parsear_esios(res.json(), zona)
    except Exception as e:
        logger.info("PVPC de ESIOS no disponible (%s), se prueba el respaldo", e)
        try:
            res = requests.get(URL_APIDATOS, timeout=ESPERA_PVPC, params={
                "start_date": f"{fecha_iso}T00:00", "end_date": f"{fecha_iso}T23:59", "time_trunc": "hour"})
            res.raise_for_status()
            horas = _parsear_apidatos(res.json())
            fuente = "mercado"
        except Exception as e2:
            logger.warning("No se han podido obtener los precios de la luz: %s", e2)

    resultado = {"fecha": fecha_iso, "zona": zona, "fuente": fuente, "horas": horas, "ts": time.time()}
    with _lock_pvpc:
        _cache_pvpc[clave] = resultado
    return resultado if horas else None


def _precio_pvpc_hora(precios, hora):
    for x in (precios or {}).get("horas") or []:
        if x["h"] == hora:
            return x["precio"]
    return None


def _mejor_ventana(precios, duracion=4, desde=0):
    """Tramo contiguo de `duracion` horas más barato a partir de `desde`.
    Es lo que de verdad interesa para decidir cuándo enchufar."""
    horas = sorted([x for x in (precios or {}).get("horas") or [] if x["h"] >= desde], key=lambda x: x["h"])
    if len(horas) < duracion:
        return None
    mejor = None
    for i in range(len(horas) - duracion + 1):
        tramo = horas[i:i + duracion]
        media = sum(x["precio"] for x in tramo) / duracion
        if mejor is None or media < mejor["media"]:
            mejor = {"inicio": tramo[0]["h"], "fin": tramo[-1]["h"] + 1, "media": media}
    return mejor


def _precio_casa(settings, fecha, precios=None):
    """Precio €/kWh de casa en un instante. Devuelve (precio, periodo).

    `precios` es el juego del PVPC y solo se usa si el modo es 'pvpc'. Si no
    hay datos de REE se cae a los tramos, que es la mejor aproximación
    disponible; el que llama debe avisar de que el precio es aproximado."""
    settings = settings or {}
    modo = settings.get("tarifaModo") or "tramos"
    if modo == "fijo":
        return _num(settings.get("tarifaFijo"), 0.15), None
    if modo == "pvpc":
        precio = _precio_pvpc_hora(precios, fecha.hour)
        if precio is not None:
            return precio, None
    periodo = _periodo_dos_tramos(settings, fecha) if modo == "dos" else _periodo_2_0td(fecha)
    # Respaldo a pDay/pNight por si el archivo viene de una versión antigua.
    respaldo = {"P1": settings.get("pDay", 0.22), "P2": 0.13, "P3": settings.get("pNight", 0.03)}
    precio = _num(settings.get("tarifa" + periodo), _num(respaldo[periodo], 0.0))
    return precio, periodo


def _precio_carga_casa(app_data, fecha_iso):
    """Precio €/kWh que se le aplica a una carga de casa según cuándo empezó.

    En modo PVPC descarga el precio real de ESE día: guardar la carga con el
    precio de los tramos falsearía el coste y, con él, todas las estadísticas."""
    settings = app_data.get("settings", {})
    fecha = _parse_iso(fecha_iso) or datetime.datetime.now()
    precios = None
    if (settings.get("tarifaModo") or "tramos") == "pvpc":
        precios = _obtener_precios_pvpc(fecha.date().isoformat(), settings.get("zonaPvpc"))
    return _precio_casa(settings, fecha, precios)


def _sincronizar_tarifa(settings, clave=None):
    """Mantiene pDay/pNight al día con tarifaP1/tarifaP3.

    Son las claves que usaban ev_manager.html y las versiones antiguas del bot.
    Ya no se leen para calcular nada, pero un backup se abre en cualquiera de los
    tres sitios y no conviene que uno enseñe un precio y otro enseñe otro."""
    if clave is not None and not str(clave).startswith("tarifa"):
        return
    settings["pDay"] = _num(settings.get("tarifaP1"), settings.get("pDay", 0.22))
    settings["pNight"] = _num(settings.get("tarifaP3"), settings.get("pNight", 0.03))


_precio_carburante_cache = {}  # (tipo, id provincia o "NACIONAL") -> {"valor":.., "ts":.., "fuente":..}
PRECIO_GASOIL_CACHE_HORAS = 6

# Carburante del coche de referencia con el que se compara el ahorro. El campo de la API oficial
# tiene que escribirse EXACTAMENTE así (se comprobó contra la respuesta real del ministerio).
CARBURANTES = {
    "gasolina95": ("Gasolina 95", "Precio Gasolina 95 E5"),
    "gasoleo": ("Gasóleo A", "Precio Gasoleo A"),
}
CARBURANTE_POR_DEFECTO = "gasolina95"


def _tipo_carburante(settings):
    """Clave del carburante de referencia configurado, con respaldo al de por defecto si el
    archivo trae un valor raro (o viene de una versión anterior, que no tenía este campo)."""
    tipo = (settings or {}).get("iceFuel") or CARBURANTE_POR_DEFECTO
    return tipo if tipo in CARBURANTES else CARBURANTE_POR_DEFECTO


def _nombre_carburante(settings):
    return CARBURANTES[_tipo_carburante(settings)][0]


_provincias_cache = {"lista": None, "ts": None}
PROVINCIAS_CACHE_HORAS = 24 * 7  # el listado de provincias españolas no cambia casi nunca


def _normalizar_texto(texto):
    """Quita tildes/diacríticos y pasa a mayúsculas, para comparar nombres de ciudad/provincia
    sin depender de que el usuario los escriba exactamente igual que la fuente oficial."""
    texto = unicodedata.normalize("NFKD", texto or "")
    texto = "".join(c for c in texto if not unicodedata.combining(c))
    return texto.strip().upper()


def _obtener_id_provincia(nombre_provincia):
    """Busca el ID numérico de una provincia española por nombre (admite tildes/mayúsculas
    distintas) usando el listado oficial (Ministerio para la Transición Ecológica), cacheado
    durante días porque prácticamente nunca cambia. Devuelve None si no se encuentra o falla."""
    nombre_norm = _normalizar_texto(nombre_provincia)
    if not nombre_norm:
        return None
    ahora = datetime.datetime.now()
    cache = _provincias_cache
    necesita_recargar = (
        cache["lista"] is None
        or not cache["ts"]
        or (ahora - cache["ts"]).total_seconds() > PROVINCIAS_CACHE_HORAS * 3600
    )
    if necesita_recargar:
        try:
            resp = requests.get(
                "https://sedeaplicaciones.minetur.gob.es/ServiciosRESTCarburantes/PreciosCarburantes/Listados/Provincias/",
                timeout=20, headers={"User-Agent": "EVBot/1.0"},
            )
            resp.raise_for_status()
            cache["lista"] = resp.json()
            cache["ts"] = ahora
        except Exception:
            logger.exception("No se pudo obtener el listado de provincias españolas")
            if cache["lista"] is None:
                return None
    for p in cache["lista"]:
        if _normalizar_texto(p.get("Provincia", "")) == nombre_norm:
            return p.get("IDPovincia")
    for p in cache["lista"]:  # coincidencia parcial, ej. "Alava" -> "ARABA/ÁLAVA"
        if nombre_norm in _normalizar_texto(p.get("Provincia", "")):
            return p.get("IDPovincia")
    return None


def _obtener_precio_carburante(provincia=None, tipo=None):
    """Consulta el precio medio actual del carburante indicado en España (API abierta oficial del
    Gobierno, Ministerio para la Transición Ecológica) para no depender de que el usuario lo busque
    a mano. Si se indica `provincia` (nombre) y se reconoce, calcula la media solo de esa provincia;
    si no, usa la media nacional. Devuelve (precio, es_nuevo, descripcion_fuente) o (None, False,
    None) si nunca se pudo obtener. Cachea unas horas para no descargar el listado en cada consulta."""
    tipo = tipo if tipo in CARBURANTES else CARBURANTE_POR_DEFECTO
    nombre_carburante, campo_api = CARBURANTES[tipo]
    id_provincia = _obtener_id_provincia(provincia) if provincia else None
    clave_cache = (tipo, id_provincia or "NACIONAL")
    ahora = datetime.datetime.now()
    cache = _precio_carburante_cache.setdefault(clave_cache, {"valor": None, "ts": None, "fuente": None})
    if cache["valor"] is not None and cache["ts"] and (ahora - cache["ts"]).total_seconds() < PRECIO_GASOIL_CACHE_HORAS * 3600:
        return cache["valor"], False, cache["fuente"]
    url = "https://sedeaplicaciones.minetur.gob.es/ServiciosRESTCarburantes/PreciosCarburantes/EstacionesTerrestres/"
    if id_provincia:
        url += f"FiltroProvincia/{id_provincia}"
    try:
        resp = requests.get(url, timeout=25, headers={"User-Agent": "EVBot/1.0"})
        resp.raise_for_status()
        datos_api = resp.json()
        precios = []
        for estacion in datos_api.get("ListaEESSPrecio", []):
            valor_txt = (estacion.get(campo_api) or "").strip()
            if not valor_txt:
                continue
            try:
                precios.append(float(valor_txt.replace(",", ".")))
            except ValueError:
                continue
        if not precios:
            return cache["valor"], False, cache["fuente"]
        media = round(sum(precios) / len(precios), 3)
        # Descripción corta a propósito: se muestra dentro de mensajes que se leen en el móvil,
        # donde "media de N gasolineras en tu provincia (X)" ocupaba dos líneas él solo.
        fuente = (
            f"{nombre_carburante}, media de {len(precios)} gasolineras, {provincia}"
            if id_provincia else
            f"{nombre_carburante}, media de {len(precios)} gasolineras"
        )
        cache["valor"] = media
        cache["ts"] = ahora
        cache["fuente"] = fuente
        return media, True, fuente
    except Exception:
        logger.exception("No se pudo obtener el precio actual de %s (se usará el último conocido o el configurado)", nombre_carburante)
        return cache["valor"], False, cache["fuente"]


def _precio_carburante_efectivo(settings):
    """Precio por litro que hay que usar en los cálculos: el de la API si el usuario lo tiene en
    automático (por defecto) y se ha podido consultar; si no, el que tenga guardado a mano.
    Devuelve (precio, texto_de_la_fuente)."""
    settings = settings or {}
    guardado = settings.get("icePrice", 0) or 0
    if settings.get("icePriceAuto") is False:
        return guardado, "puesto a mano"
    precio, _, fuente = _obtener_precio_carburante(settings.get("provincia"), _tipo_carburante(settings))
    if precio is None:
        return guardado, "último valor guardado (no he podido consultar el precio)"
    return precio, fuente


_geocode_ciudad_cache = {}  # nombre normalizado -> (lat, lon)
_temperatura_cache = {}  # (lat, lon) redondeados -> {"valor":.., "ts":..}
TEMPERATURA_CACHE_MINUTOS = 20


def _geocodificar_ciudad(nombre_ciudad):
    """Convierte un nombre de ciudad en coordenadas (lat, lon) usando Open-Meteo Geocoding (API
    gratuita, sin necesidad de clave). Cachea el resultado porque una ciudad no cambia de sitio.
    Devuelve None si no se encuentra o falla la consulta."""
    nombre_norm = _normalizar_texto(nombre_ciudad)
    if not nombre_norm:
        return None
    if nombre_norm in _geocode_ciudad_cache:
        return _geocode_ciudad_cache[nombre_norm]
    try:
        resp = requests.get(
            "https://geocoding-api.open-meteo.com/v1/search",
            params={"name": nombre_ciudad, "count": 1, "language": "es", "format": "json"},
            timeout=15,
        )
        resp.raise_for_status()
        resultados = resp.json().get("results") or []
        if not resultados:
            return None
        coords = (resultados[0]["latitude"], resultados[0]["longitude"])
        _geocode_ciudad_cache[nombre_norm] = coords
        return coords
    except Exception:
        logger.exception("No se pudo geocodificar la ciudad '%s' para consultar el tiempo", nombre_ciudad)
        return None


def _obtener_temperatura_actual(nombre_ciudad):
    """Devuelve la temperatura exterior actual (°C, redondeada) en la ciudad indicada, usando
    Open-Meteo (gratis, sin API key). Devuelve None si la ciudad no está configurada, no se
    reconoce, o falla la consulta (en ese caso se usa el último valor cacheado si lo hay)."""
    coords = _geocodificar_ciudad(nombre_ciudad)
    if not coords:
        return None
    lat, lon = coords
    clave_cache = (round(lat, 2), round(lon, 2))
    ahora = datetime.datetime.now()
    cache = _temperatura_cache.setdefault(clave_cache, {"valor": None, "ts": None})
    if cache["valor"] is not None and cache["ts"] and (ahora - cache["ts"]).total_seconds() < TEMPERATURA_CACHE_MINUTOS * 60:
        return cache["valor"]
    try:
        resp = requests.get(
            "https://api.open-meteo.com/v1/forecast",
            params={"latitude": lat, "longitude": lon, "current": "temperature_2m", "timezone": "auto"},
            timeout=15,
        )
        resp.raise_for_status()
        temp = resp.json().get("current", {}).get("temperature_2m")
        if temp is None:
            return cache["valor"]
        temp = round(temp, 1)
        cache["valor"] = temp
        cache["ts"] = ahora
        return temp
    except Exception:
        logger.exception("No se pudo obtener la temperatura actual para '%s'", nombre_ciudad)
        return cache["valor"]


# --- Botones del menú: todo se maneja pulsando botones, sin necesidad de escribir comandos.
# Las etiquetas se mantienen CORTAS a propósito: el bot se usa desde el móvil, donde Telegram
# recorta el texto de los botones que no cabe y dos etiquetas largas en la misma fila quedan
# ilegibles. El emoji hace de icono y el texto solo tiene que recordar de qué va. ---
BTN_RECARGA = "💰 Precio carga"
BTN_TIEMPO = "⏰ Desenchufar"
BTN_RAPIDA22 = "⚡ Rápida 22"
BTN_RAPIDA55 = "⚡ Rápida 55"
BTN_EQUIVALENCIAS = "🔋 Equivalencias"
BTN_AYUDA = "❓ Ayuda"
BTN_CANCELAR = "❌ Cancelar"
BTN_CASA = "🏠 En casa"
BTN_CALLE = "🛣️ En la calle"
BTN_ANOTAR = "📒 Anotar carga"
BTN_VER_CARGAS = "📊 Ver cargas"
BTN_OBD_ANOTAR = "🔧 Anotar OBD"
BTN_GASTO_ANOTAR = "🧾 Anotar gasto"
BTN_VER_OBD = "🔎 Ver OBD"
BTN_GESTIONAR = "🗂️ Editar / Borrar"
BTN_MAS = "⚙️ Más opciones"
BTN_FINALIZAR_CARGA = "🔚 Cerrar carga"

# Estilos de botón introducidos en Bot API 10: colorean el botón en el cliente.
# Los clientes antiguos simplemente ignoran el campo, así que es seguro usarlos.
ESTILO_PELIGRO = "danger"    # rojo: borrar, cancelar, sobrescribir
ESTILO_EXITO = "success"     # verde: confirmar, guardar
ESTILO_PRIMARIO = "primary"  # azul: acción principal

# Si alguna vez la API rechazase el campo "style", basta con poner esto a False
# para volver a botones sin color sin tocar nada más.
USAR_ESTILOS_BOTONES = True


def _boton_texto(texto, estilo=None):
    """Botón del teclado normal, con color opcional."""
    if estilo and USAR_ESTILOS_BOTONES:
        return KeyboardButton(texto, style=estilo)
    return KeyboardButton(texto)


def _boton_inline(texto, callback_data, estilo=None):
    """Botón inline, con color opcional."""
    if estilo and USAR_ESTILOS_BOTONES:
        return InlineKeyboardButton(texto, callback_data=callback_data, style=estilo)
    return InlineKeyboardButton(texto, callback_data=callback_data)


def teclado_menu():
    """Menú principal, agrupado por lo que hace cada bloque (anotar / consultar / calcular)
    y con dos botones por fila como máximo para que se lean bien en un móvil.

    `is_persistent=True` (Bot API 6.4+) hace que el teclado NO se pliegue tras pulsar: en el
    móvil, sin esto, el menú desaparece y hay que tocar el icono del teclado para recuperarlo,
    que es justo la fricción que no queremos en un bot que se maneja solo con botones."""
    teclado = ReplyKeyboardMarkup(
        resize_keyboard=True,
        is_persistent=True,
        input_field_placeholder="Pulsa un botón del menú 👇",
    )
    teclado.add(BTN_ANOTAR, BTN_FINALIZAR_CARGA)
    teclado.add(BTN_OBD_ANOTAR, BTN_GASTO_ANOTAR)
    teclado.add(BTN_VER_CARGAS, BTN_VER_OBD)
    teclado.add(BTN_RECARGA, BTN_TIEMPO)
    teclado.add(BTN_RAPIDA22, BTN_RAPIDA55)
    teclado.add(BTN_MAS, BTN_GESTIONAR)
    teclado.add(BTN_EQUIVALENCIAS, BTN_AYUDA)
    return teclado


def teclado_cancelar(pista=None):
    """Teclado simple para poder cancelar en cualquier momento.

    `pista` se muestra dentro del campo de escritura (`input_field_placeholder`): en el móvil
    el teclado tapa buena parte del mensaje anterior, así que recordar ahí mismo qué se espera
    ("Solo el número, ej: 50") evita tener que subir a releer la pregunta.
    El botón va en rojo (`style="danger"`, Bot API 10) para distinguirlo de un botón de acción."""
    teclado = ReplyKeyboardMarkup(
        resize_keyboard=True,
        one_time_keyboard=True,
        input_field_placeholder=pista or "Escribe tu respuesta…",
    )
    teclado.add(_boton_texto(BTN_CANCELAR, ESTILO_PELIGRO))
    return teclado


def teclado_lugar():
    teclado = ReplyKeyboardMarkup(
        resize_keyboard=True,
        one_time_keyboard=True,
        input_field_placeholder="Elige dónde vas a cargar",
    )
    teclado.add(BTN_CASA, BTN_CALLE)
    teclado.add(_boton_texto(BTN_CANCELAR, ESTILO_PELIGRO))
    return teclado


def mostrar_menu(chat_id, texto="👇 ¿Qué hacemos?", parse_mode=None):
    bot.send_message(chat_id, texto, reply_markup=teclado_menu(), parse_mode=parse_mode)


def _nombre_de(chat_id):
    """Nombre legible de quien ha anotado algo, para que el aviso diga quién ha sido.
    Se consulta a Telegram una única vez por chat y se guarda en memoria."""
    if chat_id in _nombres_chat:
        return _nombres_chat[chat_id]
    nombre = str(chat_id)
    try:
        chat = bot.get_chat(chat_id)
        nombre = chat.first_name or chat.title or chat.username or str(chat_id)
    except Exception as exc:
        logger.warning("No se pudo obtener el nombre de %s: %s", chat_id, _ocultar_token(exc))
    _nombres_chat[chat_id] = nombre
    return nombre


def _destinos_aviso(autor_chat_id):
    destinos = []
    if not EV_AVISOS_SOLO_EXTRA:
        destinos += [c for c in ALLOWED_USER_IDS if c != autor_chat_id]
    for extra in EV_AVISOS_CHAT_IDS:
        # Un grupo se avisa siempre, aunque el autor esté dentro: es el sitio donde los dos
        # lo veis, y si no, quien lo anota tendría que reenviarlo a mano.
        if extra not in destinos:
            destinos.append(extra)
    return destinos


def _avisar_a_los_demas(autor_chat_id, texto):
    """Reenvía el resumen de lo recién anotado al resto de usuarios (y/o al grupo).

    Va entero dentro de try/except a propósito: el dato YA está guardado cuando se llama, así
    que un fallo aquí (el otro usuario nunca abrió el bot -> 403, el bot no está en el grupo,
    corte de red...) no puede tumbar el flujo ni hacer creer que no se ha guardado."""
    try:
        destinos = _destinos_aviso(autor_chat_id)
        if not destinos:
            return
        aviso = f"🔔 Anotado por *{_escapar_markdown(_nombre_de(autor_chat_id))}*\n\n{texto}"
        for destino in destinos:
            try:
                bot.send_message(destino, aviso, parse_mode="Markdown")
            except Exception as exc:
                logger.warning("No se pudo avisar a %s: %s", destino, _ocultar_token(exc))
    except Exception:
        logger.exception("Error enviando los avisos")


def es_cancelacion(message):
    """Si el usuario pulsa Cancelar, se limpia todo y se vuelve al menú."""
    if message.text == BTN_CANCELAR:
        datos.pop(message.chat.id, None)
        mostrar_menu(message.chat.id, "Vale, lo he cancelado. 😊")
        return True
    return False


def _es_numero(texto):
    """Valida que el texto sea un número (admite coma/punto decimal y signo negativo)."""
    t = (texto or "").strip()
    if not t:
        return False
    if t.startswith('-'):
        t = t[1:]
    return t.replace('.', '', 1).isdigit()


def _escapar_markdown(texto):
    """Escapa caracteres especiales de Markdown (v1) en texto libre escrito por el usuario
    (marca/operador, modelo, ciudad, provincia...) antes de insertarlo en un mensaje enviado
    con parse_mode="Markdown". Sin esto, un valor con guion bajo, asterisco o backtick puede
    romper el parseo de Telegram (ApiTelegramException: can't parse entities) o alterar el formato."""
    if texto is None:
        return ""
    texto = str(texto)
    for ch in ("\\", "_", "*", "`", "["):
        texto = texto.replace(ch, "\\" + ch)
    return texto


@bot.message_handler(commands=["chatid"])
def mostrar_chat_id(message):
    """Responde con el id del chat donde se ejecuta. Sirve para averiguar el id de un grupo
    y ponerlo en EV_AVISOS_CHAT_IDS.

    Va registrado ANTES del filtro de acceso a propósito, porque en un grupo `chat.id` es el
    id del GRUPO (que nunca está en ALLOWED_USER_IDS) y el filtro lo bloquearía. Aquí se
    comprueba quién ESCRIBE (`from_user.id`), no dónde: solo tú y tu padre obtienen respuesta,
    y lo único que revela es el id del propio chat."""
    if not usuario_autorizado(message.from_user.id):
        return
    tipo = "privado" if message.chat.type == "private" else f"grupo ({message.chat.type})"
    bot.send_message(
        message.chat.id,
        f"🆔 Id de este chat: `{message.chat.id}`\nTipo: {tipo}\n\n"
        "Si es un grupo, ponlo en config.py:\n"
        f"`EV_AVISOS_CHAT_IDS = [{message.chat.id}]`",
        parse_mode="Markdown",
    )


@bot.message_handler(func=lambda m: not usuario_autorizado(m.chat.id))
def acceso_denegado(message):
    """Bloquea a cualquier usuario que no esté en ALLOWED_USER_IDS. Al estar registrado
    el primero, intercepta el mensaje antes que cualquier otro manejador."""
    logger.warning("Acceso bloqueado para chat_id=%s (usuario no autorizado)", message.chat.id)
    bot.send_message(message.chat.id, "🚫 No tienes permiso para usar este bot. Contacta con el administrador si crees que es un error.")


@bot.message_handler(commands=["start", "ayuda"])
def start(message):
    # En móvil un bloque largo de texto obliga a hacer scroll y no se lee. Por eso la ayuda va
    # en grupos cortos, con una línea por botón y sin párrafos: se escanea de un vistazo.
    texto = (
        "👋 ¡Hola! Soy *EVBot*\n"
        "Pulsa un botón de abajo 👇\n"
        "\n"
        "*📒 ANOTAR*\n"
        "📒 Anotar carga\n"
        "     Guarda una carga en el dashboard.\n"
        "🔚 Cerrar carga\n"
        "     Añade el % final y la hora de fin\n"
        "     a una carga de casa que dejaste\n"
        "     a medias.\n"
        "     Cierra la carga de casa\n"
        "     del día anterior.\n"
        "🔧 Anotar OBD\n"
        "     Guarda la salud de la batería.\n"
        "🧾 Anotar gasto\n"
        "     ITV, seguro, ruedas... con aviso\n"
        "     cuando toque repetirlo.\n"
        "🗂️ Editar / Borrar\n"
        "     Cambia o elimina lo ya guardado.\n"
        "\n"
        "*📊 CONSULTAR*\n"
        "📊 Ver cargas\n"
        "🔎 Ver OBD\n"
        "/luz Precio de la luz hoy y\n"
        "     mejor hora para enchufar.\n"
        "\n"
        "*🧮 CALCULAR*\n"
        "💰 Precio carga\n"
        "     Cuánto te costará cargar.\n"
        "⏰ Desenchufar\n"
        "     A qué hora terminará la carga.\n"
        "⚡ Rápida 22 / 55\n"
        "     Tiempo en cargadores rápidos.\n"
        "🔋 Equivalencias\n"
        "     Cuántos km da cada % de batería.\n"
        "\n"
        "*⚙️ MÁS OPCIONES*\n"
        "Resumen y ahorro, estadísticas,\n"
        "tarifas, precio del carburante y copias\n"
        "de seguridad.\n"
        "\n"
        "💡 Las fechas se escriben:\n"
        "`ahora`, `20:30`, `ayer 22:00`,\n"
        "`hace 2h` o `4/8 20:30`."
    )
    bot.send_message(message.chat.id, texto, reply_markup=teclado_menu(), parse_mode="Markdown")


@bot.message_handler(func=lambda m: m.text == BTN_AYUDA)
def ayuda_boton(message):
    start(message)


@bot.message_handler(commands=["equivalencias"])
@bot.message_handler(func=lambda m: m.text == BTN_EQUIVALENCIAS)
def equivalencias(message):
    # Tabla en monoespaciado: es la única forma de que las columnas queden alineadas en el
    # móvil (con texto normal cada línea se descuadra según el ancho de cada carácter).
    texto = (
        "🔋 *Equivalencias*\n"
        "_Batería · km · kWh_\n"
        "\n"
        "```\n"
        "  2%      5 km    1,0 kWh\n"
        " 10%     25 km    5,0 kWh\n"
        " 20%     50 km   10,0 kWh\n"
        " 25%     63 km   12,5 kWh\n"
        " 32%     80 km   16,0 kWh\n"
        " 40%    100 km   20,0 kWh\n"
        " 50%    125 km   25,0 kWh\n"
        " 60%    150 km   30,0 kWh\n"
        " 70%    175 km   35,0 kWh\n"
        " 80%    200 km   40,0 kWh\n"
        " 85%    213 km   42,5 kWh\n"
        "100%    250 km   50,0 kWh\n"
        "```\n"
        "\n"
        "_Valores orientativos._"
    )
    bot.send_message(message.chat.id, texto, reply_markup=teclado_menu(), parse_mode="Markdown")

@bot.message_handler(commands=["recarga"])
@bot.message_handler(func=lambda m: m.text == BTN_RECARGA)
def recarga(message):
    msg = bot.send_message(message.chat.id, "🔋 ¿Qué porcentaje de batería vas a cargar?\n\nEscribe solo el número, por ejemplo: 50", reply_markup=teclado_cancelar("Solo el número, ej: 50"))
    bot.register_next_step_handler(msg, porcentajeBateria)

def porcentajeBateria(message):
    if es_cancelacion(message):
        return
    bateriaPorRecargar = message.text.replace(',', '.').strip()
    if not bateriaPorRecargar.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 No te he entendido. Escribe solo el número, por ejemplo: 50", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, porcentajeBateria)
    else:
        datos[message.chat.id] = {"bateriaPorRecargar": float(bateriaPorRecargar)}
        msg = bot.send_message(message.chat.id, "📍 ¿Dónde vas a cargar el coche?", reply_markup=teclado_lugar())
        bot.register_next_step_handler(msg, dondeRecarga)

def dondeRecarga(message):
    if es_cancelacion(message):
        return
    if message.text not in (BTN_CASA, BTN_CALLE):
        msg = bot.send_message(message.chat.id, "🙈 Elige una opción pulsando uno de los botones.", reply_markup=teclado_lugar())
        bot.register_next_step_handler(msg, dondeRecarga)
    else:
        datos[message.chat.id]["lugarRecarga"] = message.text
        if message.text == BTN_CALLE:
            msg = bot.send_message(message.chat.id, "💶 ¿A cuánto está el kWh ahí? (en euros)\n\nEjemplo: 0.35", reply_markup=teclado_cancelar("Solo el número, ej: 0.35"))
            bot.register_next_step_handler(msg, precioKwhCalle)
        else:
            calcularPrecioRecarga(message)

def precioKwhCalle(message):
    if es_cancelacion(message):
        return
    precioKwhCalle = message.text.replace(',', '.').strip()
    if not precioKwhCalle.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 No te he entendido. Escribe solo el número, por ejemplo: 0.35", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, precioKwhCalle)
    else:
        datos[message.chat.id]["precioKwhCalle"] = float(precioKwhCalle)
        calcularPrecioRecarga(message)

def calcularPrecioRecarga(message):
    chat_id = message.chat.id
    kwhPorRecargar = datos[chat_id]["bateriaPorRecargar"] * KWH_BASE / PORCENTAJE_BASE
    if datos[chat_id]["lugarRecarga"] == BTN_CALLE:
        precioRecarga = kwhPorRecargar * datos[chat_id]["precioKwhCalle"]
        precioRecargaCasa = kwhPorRecargar * PRECIO_KWH_CASA
        diferenciaDePrecio = precioRecarga - precioRecargaCasa
        bot.send_message(chat_id, f"💡 En casa esta misma carga te habría costado {round(precioRecargaCasa,2)}€ (una diferencia de {round(diferenciaDePrecio,2)}€).")
    else:
        precioRecarga = kwhPorRecargar * PRECIO_KWH_CASA
    bot.send_message(chat_id, f"✅ La recarga te costará unos *{round(precioRecarga,2)}€*, cargando aproximadamente *{round(kwhPorRecargar,2)} kWh*.", parse_mode="Markdown")
    datos.pop(chat_id, None)
    mostrar_menu(chat_id)

@bot.message_handler(commands=["tiempo"])
@bot.message_handler(func=lambda m: m.text == BTN_TIEMPO)
def recargaTiempo(message):
    msg = bot.send_message(message.chat.id, "⏰ ¿Cuántos minutos va a estar cargando?\n\nEscribe solo el número, por ejemplo: 90", reply_markup=teclado_cancelar("Minutos, ej: 90"))
    bot.register_next_step_handler(msg, calculoTiempoRecarga)

def calculoTiempoRecarga(message):
    if es_cancelacion(message):
        return
    minutosRecarga = message.text.strip()
    if not minutosRecarga.isdigit():
        msg = bot.send_message(message.chat.id, "🙈 No te he entendido. Escribe solo el número de minutos, por ejemplo: 90", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, calculoTiempoRecarga)
    else:
        horaActual = datetime.datetime.now()
        horaFinalizacion = horaActual + datetime.timedelta(minutes=int(minutosRecarga))
        horaFinalString = str(horaFinalizacion.hour).zfill(2)+":"+str(horaFinalizacion.minute).zfill(2)
        msg = f"🔌 Lo has enchufado a las {horaActual.hour:02d}:{horaActual.minute:02d}h.\n\n✅ La carga terminará sobre las {horaFinalString}h."
        bot.send_message(message.chat.id, msg)
        mostrar_menu(message.chat.id)


def _datos_para_calculo(chat_id):
    """(app_data, son_tuyos). Para los cálculos rápidos, que no piden contraseña.

    Si el archivo está cifrado y no hay sesión abierta se usan los valores por
    defecto avisando de ello: es mejor dar un número aproximado y decirlo que
    negarse a calcular."""
    try:
        app_data, _ = cargar_datos(_password_lista(chat_id))
        return app_data, True
    except Exception:
        return copy.deepcopy(DEFAULT_APP_DATA), False


def _texto_carga_rapida(chat_id, soc, potencia):
    """Tiempo de carga real desde `soc` % a `potencia` kW.

    Sustituye a las constantes que había antes ('14 % en 93 minutos', '1 minuto
    por cada 1 %'), que estaban medidas en un cargador doméstico y aplicadas a
    cargadores rápidos: daban hasta 4 veces el tiempo real."""
    app_data, son_tuyos = _datos_para_calculo(chat_id)
    capacidad, soh, fuente = _capacidad_detallada(app_data)
    ahora = datetime.datetime.now()
    rendimiento = _rendimiento_carga(potencia)

    lineas = [f"⚡ *Carga a {potencia:g} kW desde el {soc} %*", ""]
    if soc >= 100:
        return "🔋 Ya está al 100 %, no hay nada que cargar."

    def tramo(hasta, etiqueta):
        minutos = _minutos_carga(capacidad, soc, hasta, potencia)
        if minutos <= 0:
            return None
        fin = ahora + datetime.timedelta(minutes=minutos)
        return f"{etiqueta}: *{_formatear_duracion(minutos)}* (sobre las {fin.strftime('%H:%M')}h)"

    for hasta, etiqueta in ((80, "🔋 Hasta el 80 %"), (100, "🔌 Hasta el 100 %")):
        linea = tramo(hasta, etiqueta)
        if linea:
            lineas.append(linea)

    kwh_bateria = capacidad * (100 - soc) / 100
    kwh_contador = kwh_bateria / rendimiento if rendimiento else kwh_bateria
    lineas += [
        "",
        f"⚙️ Batería de {round(capacidad, 1)} kWh ({fuente})",
        f"🔌 Entran {round(kwh_bateria, 1)} kWh, el contador marcará ~{round(kwh_contador, 1)} kWh",
        f"📉 Se pierde un {round((1 - rendimiento) * 100)} % en el cargador y la climatización",
    ]
    if soc < 80 and potencia > 11:
        lineas.append("💡 Del 80 al 100 % tarda casi lo mismo que todo lo anterior: en ruta, tira al 80.")
    if not son_tuyos:
        lineas.append("\n⚠️ Cálculo con los valores por defecto: abre una sesión para usar tu batería real.")
    elif fuente == "nominal":
        lineas.append("\nℹ️ Sin lecturas OBD: se usa la capacidad de fábrica, no la de hoy.")
    return "\n".join(lineas)


def _preguntar_soc_carga_rapida(message, potencia):
    datos.setdefault(message.chat.id, {})["potenciaCalculo"] = potencia
    msg = bot.send_message(
        message.chat.id,
        f"🔋 ¿Qué porcentaje de batería tiene ahora mismo?\n\nEscribe solo el número, por ejemplo: 20",
        reply_markup=teclado_cancelar("%, ej: 20"))
    bot.register_next_step_handler(msg, calculoCargaRapida)


@bot.message_handler(commands=["tiempoRealCarga22kWh"])
@bot.message_handler(func=lambda m: m.text == BTN_RAPIDA22)
def recargaTiempoReal(message):
    _preguntar_soc_carga_rapida(message, 22)


@bot.message_handler(commands=["tiempoCarga55kWh"])
@bot.message_handler(func=lambda m: m.text == BTN_RAPIDA55)
def recargaTiempoRealRapida(message):
    _preguntar_soc_carga_rapida(message, 55)


def calculoCargaRapida(message):
    if es_cancelacion(message):
        return
    texto = message.text.strip().replace(",", ".").rstrip("%").strip()
    try:
        soc = float(texto)
    except ValueError:
        soc = -1
    if not 0 <= soc <= 100:
        msg = bot.send_message(message.chat.id,
                               "🙈 Tiene que ser un número entre 0 y 100, por ejemplo: 20",
                               reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, calculoCargaRapida)
        return
    chat_id = message.chat.id
    potencia = datos.get(chat_id, {}).get("potenciaCalculo", 22)
    bot.send_message(chat_id, _texto_carga_rapida(chat_id, soc, potencia), parse_mode="Markdown")
    datos.get(chat_id, {}).pop("potenciaCalculo", None)
    mostrar_menu(chat_id)



def _intentar_borrar_mensaje(message):
    """Intenta borrar el mensaje del usuario (p.ej. uno que contiene una contraseña).
    Si el bot no tiene permisos o el chat no lo permite, falla en silencio."""
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass


# --- Protección contra intentos de adivinar la contraseña por fuerza bruta ---
_intentos_password = {}
MAX_INTENTOS_PASSWORD = 5
BLOQUEO_MINUTOS = 5


def _password_bloqueada(chat_id):
    info = _intentos_password.get(chat_id)
    if not info or not info.get("bloqueado_hasta"):
        return False
    if datetime.datetime.now() < info["bloqueado_hasta"]:
        return True
    _intentos_password.pop(chat_id, None)
    return False


def _minutos_restantes_bloqueo(chat_id):
    info = _intentos_password.get(chat_id)
    if not info or not info.get("bloqueado_hasta"):
        return 0
    restante = info["bloqueado_hasta"] - datetime.datetime.now()
    return max(1, int(restante.total_seconds() // 60) + 1)


def _registrar_intento_fallido(chat_id):
    info = _intentos_password.setdefault(chat_id, {"count": 0, "bloqueado_hasta": None})
    info["count"] += 1
    if info["count"] >= MAX_INTENTOS_PASSWORD:
        info["bloqueado_hasta"] = datetime.datetime.now() + datetime.timedelta(minutes=BLOQUEO_MINUTOS)
        info["count"] = 0
        logger.warning("chat_id=%s bloqueado %s minutos por demasiados intentos fallidos de contraseña", chat_id, BLOQUEO_MINUTOS)


def _limpiar_intentos(chat_id):
    _intentos_password.pop(chat_id, None)


# --- Limpieza de sesiones abandonadas: si un usuario empieza un flujo (p.ej. escribe la
# contraseña) y no lo termina ni pulsa Cancelar, no queremos que la contraseña en texto plano
# se quede en memoria (datos[chat_id]) para siempre. _set_password_sesion() marca la hora en la
# que se guardó, y un hilo en segundo plano purga esas sesiones pasado SESSION_TTL_MINUTOS. ---
SESSION_TTL_MINUTOS = 15


def _set_password_sesion(chat_id, password):
    """Guarda la contraseña en la sesión en memoria junto con la hora, para poder purgarla
    automáticamente si la sesión queda abandonada (ver _purgar_sesiones_caducadas)."""
    estado = datos.setdefault(chat_id, {})
    estado["password"] = password
    estado["_ts"] = datetime.datetime.now()
    _recordar_password(chat_id, password)


# --- Contraseña recordada entre acciones ---
# La sesión (datos[chat_id]) se borra al terminar cada flujo, así que sin esto el bot volvía a
# pedir la contraseña en CADA acción, aunque acabases de escribirla hace diez segundos. Aquí se
# guarda aparte, con su propia caducidad, y se renueva con cada uso: si sigues usando el bot no
# te la vuelve a pedir, y si lo dejas se olvida sola.
PASSWORD_TTL_MINUTOS = 30
_passwords_recordadas = {}  # chat_id -> {"password": str, "ts": datetime}


def _recordar_password(chat_id, password):
    _passwords_recordadas[chat_id] = {"password": password, "ts": datetime.datetime.now()}


def _password_recordada(chat_id):
    """Devuelve la contraseña que este usuario escribió hace poco (renovando su caducidad),
    la fija en config.py si la hay, o None. NO comprueba que siga siendo válida: para eso
    está _password_lista()."""
    if EV_BACKUP_PASSWORD:
        return EV_BACKUP_PASSWORD
    info = _passwords_recordadas.get(chat_id)
    if not info:
        return None
    if (datetime.datetime.now() - info["ts"]).total_seconds() > PASSWORD_TTL_MINUTOS * 60:
        _passwords_recordadas.pop(chat_id, None)
        return None
    info["ts"] = datetime.datetime.now()
    return info["password"]


def _olvidar_password(chat_id):
    _passwords_recordadas.pop(chat_id, None)


def _password_lista(chat_id):
    """Devuelve una contraseña recordada YA COMPROBADA contra el archivo actual, o None si no
    hay ninguna o la que había ya no sirve (p.ej. se cambió la contraseña desde el dashboard).
    Comprobarla aquí evita que el usuario rellene un asistente entero para que falle al guardar.
    Un fallo aquí no cuenta como intento fallido: no lo ha escrito él."""
    password = _password_recordada(chat_id)
    if password is None:
        return None
    try:
        cargar_datos(password)
    except CryptoJSError:
        _olvidar_password(chat_id)
        logger.info("La contraseña recordada de chat_id=%s ya no es válida; se pedirá de nuevo", chat_id)
        return None
    except Exception:
        logger.exception("Error comprobando la contraseña recordada")
        return None
    return password


def _purgar_sesiones_caducadas():
    limite = datetime.datetime.now() - datetime.timedelta(minutes=SESSION_TTL_MINUTOS)
    for chat_id in list(datos.keys()):
        estado = datos.get(chat_id) or {}
        ts = estado.get("_ts")
        if ts and ts < limite:
            datos.pop(chat_id, None)
            logger.info("Sesión de chat_id=%s purgada por inactividad (más de %s min)", chat_id, SESSION_TTL_MINUTOS)
    limite_pwd = datetime.datetime.now() - datetime.timedelta(minutes=PASSWORD_TTL_MINUTOS)
    for chat_id in list(_passwords_recordadas.keys()):
        info = _passwords_recordadas.get(chat_id) or {}
        if info.get("ts") and info["ts"] < limite_pwd:
            _passwords_recordadas.pop(chat_id, None)
            logger.info("Contraseña recordada de chat_id=%s olvidada por inactividad", chat_id)



def _iniciar_purgador_sesiones():
    """Lanza un hilo en segundo plano que revisa cada minuto si hay sesiones abandonadas
    (con contraseña en memoria) que llevan más de SESSION_TTL_MINUTOS sin completarse."""
    def _bucle():
        while True:
            time.sleep(60)
            try:
                _purgar_sesiones_caducadas()
            except Exception:
                logger.exception("Error purgando sesiones caducadas")

    hilo = threading.Thread(target=_bucle, daemon=True)
    hilo.start()


# Comandos que Telegram muestra en el menú "/" del cliente. Sin esto la lista sale vacía y
# los comandos solo funcionan si te los sabes de memoria. Se dejan fuera los más largos
# (tiempoRealCarga22kWh, tiempoCarga55kWh) porque en el móvil ese menú es una lista estrecha
# y esas acciones ya tienen su botón en el menú principal.
COMANDOS_MENU = [
    ("start", "Menú principal"),
    ("anotarcarga", "Anotar una carga"),
    ("finalizarcarga", "Cerrar una carga de casa"),
    ("anotarobd", "Anotar lectura OBD"),
    ("anotargasto", "Anotar un gasto del coche"),
    ("vercargas", "Ver últimas cargas"),
    ("verobd", "Ver últimos OBD"),
    ("gestionar", "Editar o borrar"),
    ("recarga", "Calcular precio de carga"),
    ("tiempo", "Cuándo desenchufar"),
    ("luz", "Precio de la luz hoy"),
    ("equivalencias", "Tabla de equivalencias"),
    ("masopciones", "Resumen, ajustes y backup"),
    ("ayuda", "Ayuda"),
]


def _registrar_comandos():
    """Publica la lista de comandos en Telegram para que aparezcan en el menú '/'.

    Es una llamada de red, así que si falla (sin conexión al arrancar) solo se avisa: el bot
    funciona igual, únicamente se queda el menú '/' con la lista anterior."""
    try:
        bot.set_my_commands([BotCommand(cmd, desc) for cmd, desc in COMANDOS_MENU])
        logger.info("Menú de comandos registrado (%s comandos)", len(COMANDOS_MENU))
    except Exception as exc:
        logger.warning("No se pudo registrar el menú de comandos: %s", _ocultar_token(exc))


@bot.message_handler(commands=["anotarcarga"])
@bot.message_handler(func=lambda m: m.text == BTN_ANOTAR)
def anotar_carga_inicio(message):
    chat_id = message.chat.id
    if _password_bloqueada(chat_id):
        mostrar_menu(chat_id, f"🚫 Demasiados intentos fallidos. Espera {_minutos_restantes_bloqueo(chat_id)} min. antes de volver a intentarlo.")
        return
    datos[chat_id] = {"nuevaCarga": {}}
    recordada = _password_lista(chat_id)
    if recordada:
        _set_password_sesion(chat_id, recordada)
        preguntar_lugar_carga(message)
    else:
        msg = bot.send_message(
            chat_id,
            "🔑 Para guardar la carga en el dashboard necesito la contraseña del archivo cifrado.\n\n"
            "Si es la primera vez, escribe la contraseña que quieras usar (la necesitarás también en el dashboard web).\n\n"
            "⚠️ Intentaré borrar tu mensaje después de leerlo por seguridad.",
            reply_markup=teclado_cancelar("Contraseña del dashboard"),
        )
        bot.register_next_step_handler(msg, recibir_password_anotar)


def recibir_password_anotar(message):
    if es_cancelacion(message):
        return
    chat_id = message.chat.id
    if _password_bloqueada(chat_id):
        mostrar_menu(chat_id, f"🚫 Demasiados intentos fallidos. Espera {_minutos_restantes_bloqueo(chat_id)} min. antes de volver a intentarlo.")
        datos.pop(chat_id, None)
        return
    password = message.text.strip()
    _intentar_borrar_mensaje(message)
    try:
        cargar_datos(password)
    except CryptoJSError:
        _registrar_intento_fallido(chat_id)
        msg = bot.send_message(chat_id, "❌ Contraseña incorrecta. Inténtalo de nuevo.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_password_anotar)
        return
    except Exception:
        logger.exception("Error leyendo el backup")
        mostrar_menu(chat_id, "⚠️ No he podido leer el archivo del dashboard. Avisa al administrador.")
        datos.pop(chat_id, None)
        return
    _limpiar_intentos(chat_id)
    datos.setdefault(chat_id, {"nuevaCarga": {}})
    _set_password_sesion(chat_id, password)
    preguntar_lugar_carga(message)


# =========================================================================
# Campos avanzados (opcionales) al anotar una carga.
# El dashboard (ev_manager.html) tiene un desplegable "Datos avanzados" con: % batería
# inicio/final, odómetro, potencia, tiempo, precondicionamiento y temperatura (y coste
# fijo/sub en carga pública). El bot antes omitía casi todos estos campos, o los rellenaba
# solo sin avisar (p.ej. la potencia en casa). Ahora se muestran todos con su valor
# automático (si lo hay) para que el usuario decida si lo acepta o pone el suyo.
# =========================================================================

def _obtener_settings_cache(chat_id, password):
    """Carga (y cachea en `datos`) la sección `settings` del backup, solo para poder mostrar
    valores automáticos/sugeridos mientras se rellena el formulario (el guardado real siempre
    relee el archivo)."""
    cache = datos.get(chat_id, {}).get("settingsCache")
    if cache is not None:
        return cache
    try:
        app_data, _ = cargar_datos(password)
        cache = app_data.get("settings", {}) or {}
    except Exception:
        cache = {}
    datos.setdefault(chat_id, {})["settingsCache"] = cache
    return cache


def _auto_potencia_casa(chat_id):
    password = datos.get(chat_id, {}).get("password")
    settings = _obtener_settings_cache(chat_id, password)
    return settings.get("homePower", 4.4) or 4.4


def _auto_precond_falso(chat_id):
    return False


def _auto_temp_actual(chat_id):
    """Temperatura exterior actual en la ciudad configurada en ⚙️ Configuración. Devuelve None
    (sin valor automático) si no hay ciudad configurada o si falla la consulta al servicio de tiempo."""
    password = datos.get(chat_id, {}).get("password")
    settings = _obtener_settings_cache(chat_id, password)
    ciudad = settings.get("ciudad") or settings.get("city")
    if not ciudad:
        return None
    return _obtener_temperatura_actual(ciudad)


def _auto_duracion_calle(chat_id):
    """Minutos entre el inicio y el fin de la carga en la calle, calculados a partir de las fechas
    reales elegidas con el selector de fecha/hora. None si aún falta alguna de las dos."""
    nueva = datos.get(chat_id, {}).get("nuevaCarga", {})
    inicio = nueva.get("fechaInicio")
    fin = nueva.get("fechaFin")
    if not inicio or not fin:
        return None
    try:
        inicio_dt = datetime.datetime.strptime(inicio, "%Y-%m-%dT%H:%M")
        fin_dt = datetime.datetime.strptime(fin, "%Y-%m-%dT%H:%M")
        return max(int((fin_dt - inicio_dt).total_seconds() // 60), 0)
    except Exception:
        return None


# Cada campo: (clave, etiqueta, tipo "num"/"bool", función que calcula el valor automático o None si no hay)
CAMPOS_AVANZADOS_HOME = [
    ("power", "⚡ Potencia (kW)", "num", _auto_potencia_casa),
    ("precond", "❄️ Precondicionamiento", "bool", _auto_precond_falso),
    ("temp", "🌡️ Temp. exterior (°C)", "num", _auto_temp_actual),
]

CAMPOS_AVANZADOS_STREET = [
    ("socStart", "🔋 % batería inicio", "num", None),
    ("socEnd", "🔋 % batería final", "num", None),
    ("odo", "🛣️ Odómetro (km)", "num", None),
    ("power", "⚡ Potencia cargador (kW)", "num", None),
    ("duration", "⏱️ Tiempo de carga (min)", "num", _auto_duracion_calle),
    ("precond", "❄️ Precondicionamiento", "bool", _auto_precond_falso),
    ("temp", "🌡️ Temp. exterior (°C)", "num", _auto_temp_actual),
    ("subCost", "💶 Coste fijo/suscripción (€)", "num", None),
]


def _buscar_campo_avanzado(prefijo, key):
    campos = CAMPOS_AVANZADOS_HOME if prefijo == "AVH" else CAMPOS_AVANZADOS_STREET
    return next((c for c in campos if c[0] == key), None)


def _valor_mostrado_avanzado(chat_id, nueva, key, tipo, auto_fn):
    if key in nueva:
        valor = nueva[key]
        if tipo == "bool":
            return f"{'Sí' if valor else 'No'} ✏️"
        return f"{valor} ✏️"
    auto_val = auto_fn(chat_id) if auto_fn else None
    if auto_val is not None:
        if tipo == "bool":
            return f"{'Sí' if auto_val else 'No'} (auto)"
        return f"{auto_val} (auto)"
    return "sin definir"


def _teclado_avanzado(chat_id, nueva, campos, prefijo):
    t = InlineKeyboardMarkup()
    for key, label, tipo, auto_fn in campos:
        valor = _valor_mostrado_avanzado(chat_id, nueva, key, tipo, auto_fn)
        t.add(InlineKeyboardButton(f"{label}: {valor}", callback_data=f"{prefijo}|{key}"))
    t.add(InlineKeyboardButton("✅ Continuar", callback_data=f"{prefijo}_OK"))
    return t


def _texto_menu_avanzado():
    return (
        "⚙️ *Datos avanzados (opcionales)*\n\n"
        "Donde pone *(auto)* es el valor que se usaría automáticamente. Pulsa un campo para "
        "aceptarlo, cambiarlo o dejarlo sin definir.\n\n"
        "Cuando termines, pulsa ✅ Continuar."
    )


def mostrar_menu_avanzado_home(message):
    chat_id = message.chat.id
    nueva = datos.get(chat_id, {}).get("nuevaCarga", {})
    bot.send_message(
        chat_id, _texto_menu_avanzado(),
        reply_markup=_teclado_avanzado(chat_id, nueva, CAMPOS_AVANZADOS_HOME, "AVH"),
        parse_mode="Markdown",
    )


def mostrar_menu_avanzado_street(message):
    chat_id = message.chat.id
    nueva = datos.get(chat_id, {}).get("nuevaCarga", {})
    bot.send_message(
        chat_id, _texto_menu_avanzado(),
        reply_markup=_teclado_avanzado(chat_id, nueva, CAMPOS_AVANZADOS_STREET, "AVS"),
        parse_mode="Markdown",
    )


def _pedir_valor_campo_avanzado(message, prefijo, key):
    chat_id = message.chat.id
    campo = _buscar_campo_avanzado(prefijo, key)
    if not campo:
        return
    _, label, tipo, auto_fn = campo
    datos.setdefault(chat_id, {})["_avanzadoActual"] = (prefijo, key)
    auto_txt = ""
    if auto_fn:
        auto_val = auto_fn(chat_id)
        if auto_val is not None:
            auto_val_txt = ("Sí" if auto_val else "No") if tipo == "bool" else auto_val
            auto_txt = f"\n\n🤖 Valor automático: {auto_val_txt}."
        elif key == "temp":
            password = datos.get(chat_id, {}).get("password")
            ajustes_cache = _obtener_settings_cache(chat_id, password)
            ciudad = ajustes_cache.get("ciudad") or ajustes_cache.get("city")
            auto_txt = (
                "\n\n💡 Configura tu ciudad en ⚙️ Configuración para que la temperatura se rellene sola."
                if not ciudad else
                "\n\n⚠️ No he podido consultar la temperatura ahora mismo."
            )
    if tipo == "bool":
        instrucciones = "Responde *sí* o *no*."
    else:
        instrucciones = "Escribe solo el número."
    instrucciones += " También puedes escribir `auto` para usar el valor automático, o `-` para dejarlo sin definir."
    msg = bot.send_message(
        chat_id,
        f"✏️ {label}\n\n{instrucciones}{auto_txt}",
        reply_markup=teclado_cancelar(),
        parse_mode="Markdown",
    )
    bot.register_next_step_handler(msg, recibir_valor_campo_avanzado)


def recibir_valor_campo_avanzado(message):
    if es_cancelacion(message):
        return
    chat_id = message.chat.id
    estado = datos.get(chat_id, {})
    actual = estado.get("_avanzadoActual")
    if not actual:
        mostrar_menu(chat_id)
        return
    prefijo, key = actual
    campo = _buscar_campo_avanzado(prefijo, key)
    if not campo:
        estado.pop("_avanzadoActual", None)
        mostrar_menu(chat_id)
        return
    _, label, tipo, auto_fn = campo
    texto = message.text.strip()
    nueva = estado.setdefault("nuevaCarga", {})

    if texto == "-":
        nueva.pop(key, None)
    elif texto.lower() == "auto":
        valor_auto = auto_fn(chat_id) if auto_fn else None
        if valor_auto is not None:
            nueva[key] = valor_auto
        else:
            nueva.pop(key, None)
    elif tipo == "bool":
        if texto.lower() in ("si", "sí", "yes", "true", "1"):
            nueva[key] = True
        elif texto.lower() in ("no", "false", "0"):
            nueva[key] = False
        else:
            msg = bot.send_message(chat_id, "🙈 Responde *sí* o *no* (o `auto` / `-`).", reply_markup=teclado_cancelar(), parse_mode="Markdown")
            bot.register_next_step_handler(msg, recibir_valor_campo_avanzado)
            return
    else:
        valor = texto.replace(',', '.')
        if not _es_numero(valor):
            msg = bot.send_message(chat_id, "🙈 Escribe solo un número (o `auto` / `-`).", reply_markup=teclado_cancelar(), parse_mode="Markdown")
            bot.register_next_step_handler(msg, recibir_valor_campo_avanzado)
            return
        nueva[key] = float(valor)

    estado.pop("_avanzadoActual", None)
    if prefijo == "AVH":
        mostrar_menu_avanzado_home(message)
    else:
        mostrar_menu_avanzado_street(message)


def preguntar_lugar_carga(message):
    msg = bot.send_message(message.chat.id, "📍 ¿Dónde has cargado?", reply_markup=teclado_lugar())
    bot.register_next_step_handler(msg, recibir_lugar_carga)


def recibir_lugar_carga(message):
    if es_cancelacion(message):
        return
    if message.text not in (BTN_CASA, BTN_CALLE):
        msg = bot.send_message(message.chat.id, "🙈 Elige una opción pulsando un botón.", reply_markup=teclado_lugar())
        bot.register_next_step_handler(msg, recibir_lugar_carga)
        return
    chat_id = message.chat.id
    if message.text == BTN_CASA:
        # La carga de casa se puede anotar al enchufar (sin saber aún el % final ni
        # la hora de fin) o al desenchufar, con todo. Se pregunta y lo que falte se
        # completa después; asumir que siempre es nocturna era la limitación anterior.
        nueva = datos[chat_id]["nuevaCarga"]
        nueva["type"] = "home"
        iniciar_selector_fecha_hora(chat_id, "H_INI")
        return
    datos[chat_id]["nuevaCarga"]["type"] = "street"
    iniciar_selector_fecha_hora(chat_id, "S_INI")


def recibir_percent_inicial_casa(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not _es_numero(valor) or not (0 <= float(valor) <= 100):
        msg = bot.send_message(message.chat.id, "🙈 Escribe un % entre 0 y 100, por ejemplo: 35", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_percent_inicial_casa)
        return
    datos.setdefault(message.chat.id, {}).setdefault("nuevaCarga", {})["socStart"] = float(valor)
    msg = bot.send_message(
        message.chat.id,
        "🚗 ¿Cuántos km parciales llevas desde la última carga?\n\nSi no lo sabes, escribe 0",
        reply_markup=teclado_cancelar(),
    )
    bot.register_next_step_handler(msg, recibir_km_parciales_casa)


def recibir_km_parciales_casa(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not _es_numero(valor):
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número de km, o 0 si no lo sabes.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_km_parciales_casa)
        return
    datos.setdefault(message.chat.id, {}).setdefault("nuevaCarga", {})["km"] = float(valor)
    msg = bot.send_message(
        message.chat.id,
        "🛣️ ¿Qué odómetro (km totales) marca el coche ahora mismo?",
        reply_markup=teclado_cancelar(),
    )
    bot.register_next_step_handler(msg, recibir_odometro_casa)


def recibir_odometro_casa(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not _es_numero(valor):
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número del odómetro.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_odometro_casa)
        return
    datos.setdefault(message.chat.id, {}).setdefault("nuevaCarga", {})["odo"] = float(valor)
    # Se pregunta ya por el fin porque una carga se puede anotar a cualquier hora:
    # si enchufas a las 15:00 y lo apuntas al desenchufar, no hay que volver mañana.
    # Y si aún no ha terminado, se deja vacío y se cierra luego.
    iniciar_selector_fecha_hora(message.chat.id, "H_FIN_NUEVA")


def preguntar_percent_final_casa(chat_id):
    msg = bot.send_message(
        chat_id,
        "🔋 ¿Con qué % ha terminado la carga?\n\nEjemplo: 80",
        reply_markup=teclado_cancelar("%, ej: 80"),
    )
    bot.register_next_step_handler(msg, recibir_percent_final_casa)


def recibir_percent_final_casa(message):
    if es_cancelacion(message):
        return
    chat_id = message.chat.id
    nueva = datos.setdefault(chat_id, {}).setdefault("nuevaCarga", {})
    valor = message.text.replace(',', '.').strip()
    if not _es_numero(valor) or not (0 <= float(valor) <= 100):
        msg = bot.send_message(chat_id, "🙈 Escribe un % entre 0 y 100, por ejemplo: 80",
                               reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_percent_final_casa)
        return
    final = float(valor)
    if final < nueva.get("socStart", 0):
        msg = bot.send_message(
            chat_id,
            f"🤔 El % final ({round(final)}%) es menor que el inicial ({round(nueva.get('socStart', 0))}%).\n\n"
            "Escribe el % final correcto.",
            reply_markup=teclado_cancelar("%, ej: 80"),
        )
        bot.register_next_step_handler(msg, recibir_percent_final_casa)
        return
    nueva["socEnd"] = final
    mostrar_menu_avanzado_home(message)


def mostrar_confirmacion_carga_casa(message):
    chat_id = message.chat.id
    nueva = datos.get(chat_id, {}).get("nuevaCarga", {})
    potencia = nueva.get("power", _auto_potencia_casa(chat_id))
    cerrada = "socEnd" in nueva
    resumen = (
        "📋 *Resumen de la carga en casa:*\n\n"
        f"🕐 Inicio: {_formatear_fecha_hora(nueva.get('fechaInicio'))}\n"
        f"🕐 Fin: {_formatear_fecha_hora(nueva.get('fechaFin')) if nueva.get('fechaFin') else 'pendiente'}\n"
        f"🔋 Batería: {_pct(nueva.get('socStart', 0))}%"
        + (f" ➜ {_pct(nueva['socEnd'])}%\n" if cerrada else " ➜ pendiente\n")
        + f"🚗 Km parciales: {nueva.get('km', 0)} km\n"
        f"🛣️ Odómetro: {nueva.get('odo', 0)} km\n"
        f"⚡ Potencia: {potencia} kW{' (auto)' if 'power' not in nueva else ''}\n"
    )
    if "precond" in nueva:
        resumen += f"❄️ Precondicionamiento: {'Sí' if nueva['precond'] else 'No'}\n"
    if "temp" in nueva:
        resumen += f"🌡️ Temp. exterior: {nueva['temp']}°C\n"
    if cerrada:
        resumen += "\n⚡ Los kWh y el coste se calculan solos al guardar.\n\n¿Guardo esta carga?"
    else:
        resumen += ("\n⏳ Queda pendiente de cerrar: cuando sepas el % final y la hora de fin, "
                    f"usa '{BTN_FINALIZAR_CARGA}' y se calculan los kWh y el coste.\n\n"
                    "¿Guardo esta carga?")
    t = InlineKeyboardMarkup()
    t.add(_boton_inline("✅ Guardar", "CL_OK", ESTILO_EXITO))
    t.add(InlineKeyboardButton("✏️ Cambiar inicio", callback_data="CL_FECHA"),
          InlineKeyboardButton("✏️ Cambiar fin", callback_data="CL_FIN_CASA"))
    t.add(InlineKeyboardButton("⚙️ Cambiar datos avanzados", callback_data="AVH_BACK"))
    t.add(_boton_inline("❌ Cancelar", "CL_NO", ESTILO_PELIGRO))
    bot.send_message(chat_id, resumen, reply_markup=t, parse_mode="Markdown")


def recibir_kwh_carga(message):
    if es_cancelacion(message):
        return
    kwh = message.text.replace(',', '.').strip()
    if not kwh.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número de kWh, por ejemplo: 25.5", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_kwh_carga)
        return
    datos[message.chat.id]["nuevaCarga"]["kwh"] = float(kwh)
    msg = bot.send_message(message.chat.id, "💶 ¿Cuánto te ha costado en total? (€)\n\nEjemplo: 8.50", reply_markup=teclado_cancelar("Solo el número, ej: 8.50"))
    bot.register_next_step_handler(msg, recibir_coste_carga)


def recibir_coste_carga(message):
    if es_cancelacion(message):
        return
    coste = message.text.replace(',', '.').strip()
    if not coste.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número, por ejemplo: 8.50", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_coste_carga)
        return
    datos[message.chat.id]["nuevaCarga"]["cost"] = float(coste)
    msg = bot.send_message(message.chat.id, "🚗 ¿Cuántos km has hecho desde la última carga?\n\nSi no lo sabes, escribe 0", reply_markup=teclado_cancelar("Km, o 0 si no lo sabes"))
    bot.register_next_step_handler(msg, recibir_km_carga)


def recibir_km_carga(message):
    if es_cancelacion(message):
        return
    km = message.text.replace(',', '.').strip()
    if not km.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número de km, o 0 si no lo sabes.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_km_carga)
        return
    datos[message.chat.id]["nuevaCarga"]["km"] = float(km)
    # Solo el flujo de calle llega aquí (el de casa se resuelve antes con datos mínimos).
    msg = bot.send_message(
        message.chat.id,
        "🏷️ ¿En qué operador has cargado? (Iberdrola, Endesa X Way, Tesla...)\n\nSi no lo sabes, escribe: Otros",
        reply_markup=teclado_cancelar(),
    )
    bot.register_next_step_handler(msg, recibir_operador_carga)


def recibir_operador_carga(message):
    if es_cancelacion(message):
        return
    # Limitamos la longitud y quitamos saltos de línea para evitar datos basura o abusivos.
    marca = message.text.strip().replace("\n", " ")[:60]
    datos[message.chat.id]["nuevaCarga"]["brand"] = marca
    iniciar_selector_fecha_hora(message.chat.id, "S_FIN")


def mostrar_confirmacion_carga(message):
    chat_id = message.chat.id
    nueva = datos.get(chat_id, {}).get("nuevaCarga", {})
    lugar_txt = "🏠 En casa" if nueva.get("type") == "home" else f"🛣️ En la calle ({_escapar_markdown(nueva.get('brand', 'Otros'))})"
    resumen = (f"📋 *Resumen de la carga:*\n\n"
               f"{lugar_txt}\n"
               f"🕐 Inicio: {_formatear_fecha_hora(nueva.get('fechaInicio'))}\n"
               f"🏁 Fin: {_formatear_fecha_hora(nueva.get('fechaFin'))}\n"
               f"🔋 {nueva.get('kwh', 0)} kWh\n"
               f"💶 {nueva.get('cost', 0)}€\n"
               f"🚗 {nueva.get('km', 0)} km\n")
    etiquetas_extra = {
        "socStart": ("🔋 % inicio", "%"), "socEnd": ("🔋 % final", "%"),
        "odo": ("🛣️ Odómetro", " km"), "power": ("⚡ Potencia", " kW"),
        "duration": ("⏱️ Tiempo", " min"), "temp": ("🌡️ Temp. exterior", "°C"),
        "subCost": ("💶 Coste fijo/sub", "€"),
    }
    extras = [f"{etiqueta}: {nueva[campo]}{unidad}" for campo, (etiqueta, unidad) in etiquetas_extra.items() if campo in nueva]
    if "precond" in nueva:
        extras.append(f"❄️ Precondicionamiento: {'Sí' if nueva['precond'] else 'No'}")
    if extras:
        resumen += "\n" + "\n".join(extras) + "\n"
    resumen += "\n¿Guardo esta carga en el dashboard?"
    t = InlineKeyboardMarkup()
    t.add(_boton_inline("✅ Guardar", "CL_OK", ESTILO_EXITO))
    t.add(InlineKeyboardButton("✏️ Cambiar inicio", callback_data="CL_FECHA_INI"), InlineKeyboardButton("✏️ Cambiar fin", callback_data="CL_FECHA_FIN"))
    t.add(InlineKeyboardButton("⚙️ Cambiar datos avanzados", callback_data="AVS_BACK"))
    t.add(_boton_inline("❌ Cancelar", "CL_NO", ESTILO_PELIGRO))
    bot.send_message(chat_id, resumen, reply_markup=t, parse_mode="Markdown")


def _energia_y_coste_casa(app_data, soc_inicial, soc_final, fecha_inicio):
    """kWh metidos en la batería y lo que cuestan, a partir de los dos porcentajes.

    Es la misma cuenta tanto si la carga se cierra al anotarla como si se cierra
    días después, así que vive aquí y no duplicada en los dos sitios.
    Devuelve (kwh, coste, periodo_tarifario)."""
    capacidad = _capacidad_efectiva(app_data)
    kwh = max(round(capacidad * (_num(soc_final) - _num(soc_inicial)) / 100, 2), 0)
    tarifa, periodo = _precio_carga_casa(app_data, fecha_inicio)
    return kwh, round(kwh * tarifa, 2), periodo


def _minutos_entre(inicio_iso, fin_iso):
    """Duración en minutos, o None si falta alguna fecha o el fin es anterior al inicio."""
    inicio = _parse_iso(inicio_iso)
    fin = _parse_iso(fin_iso)
    if inicio is None or fin is None:
        return None
    minutos = int((fin - inicio).total_seconds() // 60)
    return minutos if minutos >= 0 else None


def _pct(valor):
    """Porcentaje sin el '.0' de sobra: el coche muestra enteros, pero el bot
    acepta decimales y '30.0%' en un resumen queda raro."""
    numero = _num(valor)
    return str(int(numero)) if numero == int(numero) else str(round(numero, 1))


def _guardar_carga_confirmada(chat_id):
    estado = datos.get(chat_id, {})
    password = estado.get("password")
    nueva = estado.get("nuevaCarga", {})

    try:
        app_data, es_nuevo = cargar_datos(password)
    except CryptoJSError:
        mostrar_menu(chat_id, "❌ La contraseña ya no es válida. Vuelve a intentarlo desde el menú.")
        datos.pop(chat_id, None)
        return
    except Exception:
        logger.exception("Error leyendo el backup al guardar")
        mostrar_menu(chat_id, "⚠️ No he podido guardar la carga. Avisa al administrador.")
        datos.pop(chat_id, None)
        return

    if nueva.get("type") == "home" and "socStart" in nueva:
        # Carga en casa. Puede guardarse ya cerrada (si al anotarla se sabía el % final y la hora
        # de fin) o quedar pendiente: se enchufa por la tarde, se anota en ese momento y el % final
        # se añade luego. La fecha/hora de inicio es la elegida por el usuario con el selector,
        # nunca el momento en que se está rellenando el formulario.
        settings = app_data.get("settings", {})
        fecha_inicio = nueva.get("fechaInicio") or datetime.datetime.now().strftime("%Y-%m-%dT%H:%M")
        cerrada = "socEnd" in nueva
        entrada = {
            "id": int(datetime.datetime.now().timestamp() * 1000),
            "date": fecha_inicio,
            "km": nueva.get("km", 0),
            "kwh": 0,
            "cost": 0,
            "type": "home",
            "socStart": nueva.get("socStart", 0),
            "odo": nueva.get("odo", 0),
            "power": nueva.get("power", settings.get("homePower", 4.4)),
            "pendingFinal": not cerrada,
        }
        if nueva.get("fechaFin"):
            entrada["dateEnd"] = nueva["fechaFin"]
        periodo = None
        if cerrada:
            entrada["socEnd"] = nueva["socEnd"]
            kwh, coste, periodo = _energia_y_coste_casa(
                app_data, entrada["socStart"], entrada["socEnd"], fecha_inicio)
            entrada["kwh"] = kwh
            entrada["cost"] = coste
            duracion = _minutos_entre(fecha_inicio, entrada.get("dateEnd"))
            if duracion is not None:
                entrada["duration"] = duracion
        if "precond" in nueva:
            entrada["precond"] = nueva["precond"]
        if "temp" in nueva:
            entrada["temp"] = nueva["temp"]
        app_data.setdefault("logs", []).append(entrada)
        try:
            guardar_datos(app_data, password)
        except Exception:
            logger.exception("Error escribiendo el backup")
            mostrar_menu(chat_id, "⚠️ No he podido guardar la carga en el archivo. Avisa al administrador.")
            datos.pop(chat_id, None)
            return
        if cerrada:
            detalle = (
                f"🏠 Carga de casa\n"
                f"🕐 {_formatear_fecha_hora(fecha_inicio)}\n"
                f"🔋 {_pct(entrada['socStart'])}% ➜ {_pct(entrada['socEnd'])}%\n"
                f"⚡ {entrada['kwh']} kWh (estimado según la batería)\n"
                f"💶 {entrada['cost']}€ (tarifa {ETIQUETA_PERIODO.get(periodo, 'precio fijo')})\n"
                f"🚗 {entrada['km']} km parciales · Odómetro: {entrada['odo']} km"
            )
            detalle += _texto_ahorro_carga(app_data, entrada["cost"], entrada["km"])
            resumen = "✅ ¡Carga guardada!\n\n" + detalle
        else:
            detalle = (
                f"🏠 Carga de casa (pendiente de cerrar)\n"
                f"🕐 Inicio: {_formatear_fecha_hora(fecha_inicio)}\n"
                f"🔋 % inicial: {_pct(entrada['socStart'])}%\n"
                f"🚗 Km parciales: {entrada['km']} km · Odómetro: {entrada['odo']} km"
            )
            resumen = (
                "✅ ¡Carga guardada!\n\n"
                + detalle
                + f"\n\n⏳ Cuando termine, usa '{BTN_FINALIZAR_CARGA}' para indicar el % final y "
                "la hora de fin; los kWh y el coste se calculan solos."
            )
        if es_nuevo:
            resumen += "\n\n📁 Se ha creado un archivo nuevo. Usa esta misma contraseña en el dashboard web para verlo."
        datos.pop(chat_id, None)
        mostrar_menu(chat_id, resumen, parse_mode="Markdown")
        _avisar_a_los_demas(chat_id, detalle)
        return

    # Flujo normal (carga pública / calle): inicio y fin son las fechas/horas reales elegidas por
    # el usuario con el selector, no el momento en que se rellena el formulario.
    entrada = {
        "id": int(datetime.datetime.now().timestamp() * 1000),
        "date": nueva.get("fechaInicio") or datetime.datetime.now().strftime("%Y-%m-%dT%H:%M"),
        "km": nueva.get("km", 0),
        "kwh": nueva.get("kwh", 0),
        "cost": nueva.get("cost", 0),
        "type": nueva.get("type", "home"),
    }
    if nueva.get("fechaFin"):
        entrada["dateEnd"] = nueva["fechaFin"]
    if nueva.get("type") == "street" and nueva.get("brand"):
        entrada["brand"] = nueva["brand"]
    for campo in ("socStart", "socEnd", "odo", "power", "duration", "precond", "temp", "subCost"):
        if campo in nueva:
            entrada[campo] = nueva[campo]
    if "duration" not in entrada:
        duracion_auto = _auto_duracion_calle(chat_id)
        if duracion_auto is not None:
            entrada["duration"] = duracion_auto

    app_data.setdefault("logs", []).append(entrada)

    try:
        guardar_datos(app_data, password)
    except Exception:
        logger.exception("Error escribiendo el backup")
        mostrar_menu(chat_id, "⚠️ No he podido guardar la carga en el archivo. Avisa al administrador.")
        datos.pop(chat_id, None)
        return

    lugar_txt = "🏠 en casa" if entrada["type"] == "home" else f"🛣️ en la calle ({_escapar_markdown(entrada.get('brand', 'Otros'))})"
    detalle = (f"{lugar_txt}\n"
               f"🕐 {_formatear_fecha_hora(entrada['date'])}\n"
               f"🔋 {entrada['kwh']} kWh\n"
               f"💶 {entrada['cost']}€\n"
               f"🚗 {entrada['km']} km")
    detalle += _texto_ahorro_carga(app_data, entrada["cost"], entrada["km"])
    resumen = "✅ ¡Carga guardada en el dashboard!\n\n" + detalle
    if es_nuevo:
        resumen += "\n\n📁 Se ha creado un archivo nuevo. Usa esta misma contraseña en el dashboard web para verlo."
    datos.pop(chat_id, None)
    mostrar_menu(chat_id, resumen, parse_mode="Markdown")
    _avisar_a_los_demas(chat_id, detalle)


@bot.message_handler(commands=["finalizarcarga"])
@bot.message_handler(func=lambda m: m.text == BTN_FINALIZAR_CARGA)
def finalizar_carga_inicio(message):
    chat_id = message.chat.id
    if _password_bloqueada(chat_id):
        mostrar_menu(chat_id, f"🚫 Demasiados intentos fallidos. Espera {_minutos_restantes_bloqueo(chat_id)} min. antes de volver a intentarlo.")
        return
    datos[chat_id] = {}
    recordada = _password_lista(chat_id)
    if recordada:
        _set_password_sesion(chat_id, recordada)
        _iniciar_finalizar_carga(message, recordada)
    else:
        msg = bot.send_message(chat_id, "🔑 Escribe la contraseña del dashboard para cerrar la carga.", reply_markup=teclado_cancelar("Contraseña del dashboard"))
        bot.register_next_step_handler(msg, recibir_password_finalizar)


def recibir_password_finalizar(message):
    if es_cancelacion(message):
        return
    chat_id = message.chat.id
    if _password_bloqueada(chat_id):
        mostrar_menu(chat_id, f"🚫 Demasiados intentos fallidos. Espera {_minutos_restantes_bloqueo(chat_id)} min. antes de volver a intentarlo.")
        datos.pop(chat_id, None)
        return
    password = message.text.strip()
    _intentar_borrar_mensaje(message)
    try:
        cargar_datos(password)
    except CryptoJSError:
        _registrar_intento_fallido(chat_id)
        msg = bot.send_message(chat_id, "❌ Contraseña incorrecta. Inténtalo de nuevo.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_password_finalizar)
        return
    except Exception:
        logger.exception("Error leyendo el backup")
        mostrar_menu(chat_id, "⚠️ No he podido leer el archivo del dashboard. Avisa al administrador.")
        datos.pop(chat_id, None)
        return
    _limpiar_intentos(chat_id)
    _set_password_sesion(chat_id, password)
    _iniciar_finalizar_carga(message, password)


def _iniciar_finalizar_carga(message, password):
    chat_id = message.chat.id
    try:
        app_data, _ = cargar_datos(password)
    except Exception:
        logger.exception("Error leyendo el backup al buscar cargas pendientes")
        mostrar_menu(chat_id, "⚠️ No he podido leer el archivo del dashboard.")
        datos.pop(chat_id, None)
        return
    pendientes = [
        l for l in app_data.get("logs", [])
        if l.get("type") == "home" and l.get("pendingFinal") is True
    ]
    if not pendientes:
        mostrar_menu(chat_id, f"📭 No hay ninguna carga de casa pendiente de cerrar. Usa '{BTN_ANOTAR}' para registrar una nueva.")
        datos.pop(chat_id, None)
        return
    pendientes.sort(key=lambda l: l.get("date", ""), reverse=True)
    if len(pendientes) == 1:
        _preguntar_percent_final_pendiente(chat_id, pendientes[0])
        return
    # Con varias cargas al día ya no vale con coger la última: hay que elegir cuál se cierra.
    t = InlineKeyboardMarkup()
    for l in pendientes[:8]:
        t.add(InlineKeyboardButton(
            f"🔌 {_formatear_fecha_hora(l.get('date'))} · desde {round(_num(l.get('socStart')))}%",
            callback_data=f"FIN|{l.get('id')}"))
    t.add(_boton_inline("❌ Cancelar", "CL_NO", ESTILO_PELIGRO))
    bot.send_message(chat_id, "🔌 ¿Qué carga quieres cerrar?", reply_markup=t)


def _preguntar_percent_final_pendiente(chat_id, log):
    datos.setdefault(chat_id, {})["finalizarCargaId"] = log.get("id")
    msg = bot.send_message(
        chat_id,
        f"🔋 La carga del {_formatear_fecha_hora(log.get('date'))} empezó al {_pct(log.get('socStart', 0))}%.\n\n"
        "¿Con qué % ha terminado la carga? (0-100)",
        reply_markup=teclado_cancelar("%, ej: 80"),
    )
    bot.register_next_step_handler(msg, recibir_percent_final_pendiente)


def recibir_percent_final_pendiente(message):
    if es_cancelacion(message):
        return
    chat_id = message.chat.id
    valor = message.text.replace(',', '.').strip()
    if not _es_numero(valor) or not (0 <= float(valor) <= 100):
        msg = bot.send_message(chat_id, "🙈 Escribe un % entre 0 y 100.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_percent_final_pendiente)
        return
    estado = datos.get(chat_id, {})
    if estado.get("finalizarCargaId") is None:
        mostrar_menu(chat_id, f"⚠️ Esta operación ha caducado. Vuelve a pulsar '{BTN_FINALIZAR_CARGA}'.")
        datos.pop(chat_id, None)
        return
    estado["finalizarPercentFinal"] = float(valor)
    iniciar_selector_fecha_hora(chat_id, "H_FIN")


def _completar_carga_pendiente(chat_id, fecha_fin_iso):
    """Guarda el % final y la fecha/hora REAL de fin (elegida con el selector, no el momento en
    que se rellena el formulario) de la carga de casa pendiente, calculando kWh, coste y duración
    reales."""
    estado = datos.get(chat_id, {})
    password = estado.get("password")
    log_id = estado.get("finalizarCargaId")
    percent_final = estado.get("finalizarPercentFinal")
    if log_id is None or percent_final is None:
        mostrar_menu(chat_id, f"⚠️ Esta operación ha caducado. Vuelve a pulsar '{BTN_FINALIZAR_CARGA}'.")
        datos.pop(chat_id, None)
        return
    try:
        app_data, _ = cargar_datos(password)
    except CryptoJSError:
        mostrar_menu(chat_id, "❌ La contraseña ya no es válida. Vuelve a intentarlo desde el menú.")
        datos.pop(chat_id, None)
        return
    except Exception:
        logger.exception("Error leyendo el backup al finalizar la carga")
        mostrar_menu(chat_id, "⚠️ No se pudo guardar el dato.")
        datos.pop(chat_id, None)
        return
    log = _buscar_por_id(app_data.get("logs", []), log_id)
    if not log:
        mostrar_menu(chat_id, "⚠️ Esa carga ya no existe (puede que se haya borrado).")
        datos.pop(chat_id, None)
        return

    percent_inicial = log.get("socStart", 0)
    kwh, coste, periodo = _energia_y_coste_casa(app_data, percent_inicial, percent_final, log.get("date"))
    log["socEnd"] = percent_final
    log["kwh"] = kwh
    log["cost"] = coste
    log["pendingFinal"] = False
    if fecha_fin_iso:
        log["dateEnd"] = fecha_fin_iso
        duracion = _minutos_entre(log.get("date"), fecha_fin_iso)
        if duracion is not None:
            log["duration"] = duracion

    try:
        guardar_datos(app_data, password)
    except Exception:
        logger.exception("Error guardando el % final de la carga")
        mostrar_menu(chat_id, "⚠️ No se pudo guardar el cambio en el archivo.")
        datos.pop(chat_id, None)
        return

    datos.pop(chat_id, None)
    tarifa_txt = ETIQUETA_PERIODO.get(periodo, "precio fijo")
    detalle = (
        f"🏠 Carga de casa completada\n"
        f"🕐 Fin: {_formatear_fecha_hora(fecha_fin_iso) if fecha_fin_iso else 'sin anotar'}\n"
        f"🔋 {_pct(percent_inicial)}% ➜ {_pct(percent_final)}%\n"
        f"⚡ {log['kwh']} kWh cargados (estimado según la capacidad de la batería)\n"
        f"💶 {log['cost']}€ (tarifa {tarifa_txt})\n"
    )
    if log.get("duration"):
        detalle += f"⏱️ Duración real: {log['duration']} min\n"
    detalle += f"🚗 {log.get('km', 0)} km parciales · Odómetro: {log.get('odo', 0)} km"
    detalle += _texto_ahorro_carga(app_data, log["cost"], log.get("km", 0))
    mostrar_menu(chat_id, "✅ ¡Carga completada!\n\n" + detalle, parse_mode="Markdown")
    _avisar_a_los_demas(chat_id, detalle)


@bot.message_handler(commands=["vercargas"])
@bot.message_handler(func=lambda m: m.text == BTN_VER_CARGAS)
def ver_cargas_inicio(message):
    chat_id = message.chat.id
    if _password_bloqueada(chat_id):
        mostrar_menu(chat_id, f"🚫 Demasiados intentos fallidos. Espera {_minutos_restantes_bloqueo(chat_id)} min. antes de volver a intentarlo.")
        return
    datos[chat_id] = {}
    recordada = _password_lista(chat_id)
    if recordada:
        mostrar_ultimas_cargas(message, recordada)
    else:
        msg = bot.send_message(chat_id, "🔑 Escribe la contraseña del dashboard para ver las últimas cargas.", reply_markup=teclado_cancelar("Contraseña del dashboard"))
        bot.register_next_step_handler(msg, recibir_password_ver)


def recibir_password_ver(message):
    if es_cancelacion(message):
        return
    chat_id = message.chat.id
    if _password_bloqueada(chat_id):
        mostrar_menu(chat_id, f"🚫 Demasiados intentos fallidos. Espera {_minutos_restantes_bloqueo(chat_id)} min. antes de volver a intentarlo.")
        datos.pop(chat_id, None)
        return
    password = message.text.strip()
    _intentar_borrar_mensaje(message)
    mostrar_ultimas_cargas(message, password)


def mostrar_ultimas_cargas(message, password):
    chat_id = message.chat.id
    try:
        app_data, _ = cargar_datos(password)
    except CryptoJSError:
        _registrar_intento_fallido(chat_id)
        msg = bot.send_message(chat_id, "❌ Contraseña incorrecta. Inténtalo de nuevo o pulsa Cancelar.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_password_ver)
        return
    except Exception:
        logger.exception("Error leyendo el backup para ver cargas")
        mostrar_menu(chat_id, "⚠️ No he podido leer el archivo del dashboard.")
        datos.pop(chat_id, None)
        return

    _limpiar_intentos(chat_id)
    datos.pop(chat_id, None)
    logs = app_data.get("logs", [])
    if not logs:
        mostrar_menu(chat_id, "📭 Todavía no hay cargas guardadas.")
        return

    ultimas = sorted(logs, key=lambda l: l.get("date", ""), reverse=True)[:5]
    # Una línea por carga con todos los datos seguidos se parte por la mitad en la pantalla de
    # un móvil y se lee fatal. Se muestra como ficha de dos líneas, separadas por un espacio.
    lineas = [f"📊 *Últimas {len(ultimas)} cargas*"]
    for l in ultimas:
        lugar = "🏠 Casa" if l.get("type") == "home" else f"🛣️ {_escapar_markdown(l.get('brand', 'Calle'))}"
        lineas.append("")
        lineas.append(f"*{_fecha_corta(l.get('date'))}* · {lugar}")
        if l.get("pendingFinal"):
            lineas.append(f"⏳ Sin cerrar (desde el {_pct(l.get('socStart', 0))}%)")
        else:
            lineas.append(f"🔋 {l.get('kwh', 0)} kWh   💶 {l.get('cost', 0)} €")
    bot.send_message(chat_id, "\n".join(lineas), parse_mode="Markdown")
    mostrar_menu(chat_id)


# =========================================================================
# Utilidades genéricas de contraseña (usadas por OBD y por Editar/Borrar)
# =========================================================================

def _requiere_password(message, siguiente_callback):
    """Ejecuta siguiente_callback(message, password) usando la contraseña global si existe,
    o pidiéndola al usuario (una sola vez) en caso contrario."""
    chat_id = message.chat.id
    if _password_bloqueada(chat_id):
        mostrar_menu(chat_id, f"🚫 Demasiados intentos fallidos. Espera {_minutos_restantes_bloqueo(chat_id)} min. antes de volver a intentarlo.")
        datos.pop(chat_id, None)
        return
    if EV_BACKUP_PASSWORD:
        _set_password_sesion(chat_id, EV_BACKUP_PASSWORD)
        siguiente_callback(message, EV_BACKUP_PASSWORD)
    else:
        recordada = _password_lista(chat_id)
        if recordada:
            _set_password_sesion(chat_id, recordada)
            siguiente_callback(message, recordada)
            return
        datos.setdefault(chat_id, {})["_next_password_cb"] = siguiente_callback
        msg = bot.send_message(
            chat_id,
            "🔑 Escribe la contraseña del archivo del dashboard.\n\n⚠️ Borraré tu mensaje después de leerlo.",
            reply_markup=teclado_cancelar("Contraseña del dashboard"),
        )
        bot.register_next_step_handler(msg, _recibir_password_generico)


def _recibir_password_generico(message):
    if es_cancelacion(message):
        return
    chat_id = message.chat.id
    if _password_bloqueada(chat_id):
        mostrar_menu(chat_id, f"🚫 Demasiados intentos fallidos. Espera {_minutos_restantes_bloqueo(chat_id)} min. antes de volver a intentarlo.")
        datos.pop(chat_id, None)
        return
    password = message.text.strip()
    _intentar_borrar_mensaje(message)
    cb = datos.get(chat_id, {}).get("_next_password_cb")
    if cb is None:
        mostrar_menu(chat_id)
        return
    try:
        cargar_datos(password)
    except CryptoJSError:
        _registrar_intento_fallido(chat_id)
        msg = bot.send_message(chat_id, "❌ Contraseña incorrecta. Inténtalo de nuevo.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, _recibir_password_generico)
        return
    except Exception:
        logger.exception("Error leyendo el backup")
        mostrar_menu(chat_id, "⚠️ No he podido leer el archivo del dashboard. Avisa al administrador.")
        datos.pop(chat_id, None)
        return
    _limpiar_intentos(chat_id)
    _set_password_sesion(chat_id, password)
    datos[chat_id].pop("_next_password_cb", None)
    cb(message, password)


def _buscar_por_id(lista, id_valor):
    for item in lista:
        if str(item.get("id")) == str(id_valor):
            return item
    return None


# =========================================================================
# Registrar lectura de batería (OBD) — añade a app_data["obd"]
# =========================================================================

@bot.message_handler(commands=["anotarobd"])
@bot.message_handler(func=lambda m: m.text == BTN_OBD_ANOTAR)
def anotar_obd_inicio(message):
    datos[message.chat.id] = {"nuevoObd": {}}
    _requiere_password(message, lambda m, pwd: iniciar_selector_fecha_hora(m.chat.id, "OBD"))


def preguntar_soh_obd(message):
    msg = bot.send_message(message.chat.id, "🔋 ¿Qué SoH (salud de batería, en %) marca el OBD?\n\nEjemplo: 92.5", reply_markup=teclado_cancelar("Solo el número, ej: 92.5"))
    bot.register_next_step_handler(msg, recibir_soh_obd)


def recibir_soh_obd(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not valor.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número, por ejemplo: 92.5", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_soh_obd)
        return
    datos[message.chat.id]["nuevoObd"]["soh"] = float(valor)
    msg = bot.send_message(message.chat.id, "🚗 ¿Cuántos km tiene el odómetro?\n\nEjemplo: 45000", reply_markup=teclado_cancelar("Solo el número, ej: 45000"))
    bot.register_next_step_handler(msg, recibir_odo_obd)


def recibir_odo_obd(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not valor.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número de km.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_odo_obd)
        return
    datos[message.chat.id]["nuevoObd"]["odo"] = float(valor)
    msg = bot.send_message(message.chat.id, "🔢 ¿Capacidad real en kWh? (Escribe 0 si no lo sabes)", reply_markup=teclado_cancelar("kWh, o 0 si no lo sabes"))
    bot.register_next_step_handler(msg, recibir_cap_obd)


def recibir_cap_obd(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not valor.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número, o 0 si no lo sabes.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_cap_obd)
        return
    datos[message.chat.id]["nuevoObd"]["cap"] = float(valor)
    msg = bot.send_message(message.chat.id, "⚖️ ¿Desbalanceo en mV? (Escribe 0 si no lo sabes)", reply_markup=teclado_cancelar("mV, o 0 si no lo sabes"))
    bot.register_next_step_handler(msg, recibir_mv_obd)


def recibir_mv_obd(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not valor.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número, o 0 si no lo sabes.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_mv_obd)
        return
    datos[message.chat.id]["nuevoObd"]["mv"] = float(valor)
    msg = bot.send_message(message.chat.id, "🔁 ¿Cuántos ciclos de carga? (Escribe 0 si no lo sabes)", reply_markup=teclado_cancelar("Ciclos, o 0 si no lo sabes"))
    bot.register_next_step_handler(msg, recibir_cycles_obd)


def recibir_cycles_obd(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not valor.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número, o 0 si no lo sabes.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_cycles_obd)
        return
    datos[message.chat.id]["nuevoObd"]["cycles"] = float(valor)
    mostrar_confirmacion_obd(message)


def mostrar_confirmacion_obd(message):
    chat_id = message.chat.id
    nuevo = datos.get(chat_id, {}).get("nuevoObd", {})
    resumen = (f"📋 *Resumen del registro de batería:*\n\n"
               f"🕐 Fecha: {_formatear_fecha_solo(nuevo.get('fecha'))}\n"
               f"🔋 SoH: {nuevo.get('soh', 0)}%\n"
               f"🚗 Odómetro: {nuevo.get('odo', 0)} km\n"
               f"🔢 Capacidad: {nuevo.get('cap', 0)} kWh\n"
               f"⚖️ Desbalanceo: {nuevo.get('mv', 0)} mV\n"
               f"🔁 Ciclos: {nuevo.get('cycles', 0)}\n\n"
               f"¿Guardo este registro?")
    t = InlineKeyboardMarkup()
    t.add(
        _boton_inline("✅ Guardar", "CO_OK", ESTILO_EXITO),
        _boton_inline("❌ Cancelar", "CO_NO", ESTILO_PELIGRO),
    )
    bot.send_message(chat_id, resumen, reply_markup=t, parse_mode="Markdown")


def _guardar_obd_confirmado(chat_id):
    estado = datos.get(chat_id, {})
    password = estado.get("password")
    nuevo = estado.get("nuevoObd", {})

    try:
        app_data, es_nuevo = cargar_datos(password)
    except CryptoJSError:
        mostrar_menu(chat_id, "❌ La contraseña ya no es válida. Vuelve a intentarlo desde el menú.")
        datos.pop(chat_id, None)
        return
    except Exception:
        logger.exception("Error leyendo el backup al guardar OBD")
        mostrar_menu(chat_id, "⚠️ No he podido guardar el registro. Avisa al administrador.")
        datos.pop(chat_id, None)
        return

    entrada = {
        "id": int(datetime.datetime.now().timestamp() * 1000),
        "date": nuevo.get("fecha") or datetime.datetime.now().strftime("%Y-%m-%d"),
        "soh": nuevo.get("soh", 0),
        "odo": nuevo.get("odo", 0),
        "cap": nuevo.get("cap", 0),
        "mv": nuevo.get("mv", 0),
        "cycles": nuevo.get("cycles", 0),
    }
    app_data.setdefault("obd", []).append(entrada)

    try:
        guardar_datos(app_data, password)
    except Exception:
        logger.exception("Error escribiendo el backup OBD")
        mostrar_menu(chat_id, "⚠️ No he podido guardar el registro en el archivo. Avisa al administrador.")
        datos.pop(chat_id, None)
        return

    detalle = (f"🔧 Lectura OBD\n"
               f"🔋 SoH: {entrada['soh']}%\n"
               f"🚗 Odómetro: {entrada['odo']} km\n"
               f"🔢 Capacidad: {entrada['cap']} kWh")
    resumen = "✅ ¡Registro de batería guardado!\n\n" + detalle
    if es_nuevo:
        resumen += "\n\n📁 Se ha creado un archivo nuevo. Usa esta misma contraseña en el dashboard web para verlo."
    datos.pop(chat_id, None)
    mostrar_menu(chat_id, resumen)
    _avisar_a_los_demas(chat_id, detalle)


# =========================================================================
#  GASTOS DEL COCHE (ITV, seguro, neumáticos...)
#  El bot ya los sumaba en el resumen pero no dejaba crearlos: había que abrir
#  la extensión para anotar una ITV. Mismas claves que shared/model.js.
# =========================================================================

def _odometro_actual(app_data):
    """Kilómetros más recientes que se conocen. El usuario los apunta en sitios
    distintos (OBD, cargas, gastos), así que se mira en los tres."""
    valores = []
    for o in app_data.get("obd") or []:
        valores.append((str(o.get("date") or ""), _num(o.get("odo"))))
    for l in app_data.get("logs") or []:
        if l.get("odo"):
            valores.append((str(l.get("date") or ""), _num(l.get("odo"))))
    for g in app_data.get("gastos") or []:
        if g.get("odo"):
            valores.append((str(g.get("date") or ""), _num(g.get("odo"))))
    if not valores:
        return 0
    valores.sort(key=lambda x: x[0])
    return max(valores[-1][1], max(v for _, v in valores))


def _normalizar_concepto_gasto(concepto):
    """Para agrupar los avisos de vencimiento: dos gastos del mismo tipo que solo
    difieren en el año escrito en el concepto ("ITV" vs "ITV 2026"), en tildes o
    en mayúsculas/espacios deben verse como EL MISMO recordatorio. Si no, cada
    renovación con un texto ligeramente distinto generaría un aviso duplicado
    además del correcto (uno "vivo" con la fecha nueva y otro "fantasma" con la
    vieja, ya superada, que nunca deja de avisar)."""
    texto = _normalizar_texto(concepto).lower()
    texto = re.sub(r"\d+", "", texto)
    return re.sub(r"\s+", " ", texto).strip()


@bot.message_handler(commands=["anotargasto"])
@bot.message_handler(func=lambda m: m.text == BTN_GASTO_ANOTAR)
def anotar_gasto_inicio(message):
    datos[message.chat.id] = {"nuevoGasto": {}}
    _requiere_password(message, lambda m, pwd: iniciar_selector_fecha_hora(m.chat.id, "GASTO"))


def preguntar_tipo_gasto(chat_id):
    t = InlineKeyboardMarkup()
    claves = list(TIPOS_GASTO.items())
    for i in range(0, len(claves), 2):
        fila = [InlineKeyboardButton(nombre, callback_data="GT|" + clave)
                for clave, nombre in claves[i:i + 2]]
        t.add(*fila)
    t.add(_boton_inline("❌ Cancelar", "CG_NO", ESTILO_PELIGRO))
    bot.send_message(chat_id, "🧾 ¿Qué tipo de gasto es?", reply_markup=t)


def recibir_tipo_gasto(chat_id, clave):
    datos.setdefault(chat_id, {}).setdefault("nuevoGasto", {})["tipo"] = clave
    msg = bot.send_message(
        chat_id,
        f"✍️ ¿Qué concepto le pongo?\n\nEjemplo: revisión de los 40.000, ITV 2026…\n"
        f"Escribe `-` para dejarlo en «{TIPOS_GASTO[clave]}».",
        reply_markup=teclado_cancelar("Concepto, o - para dejarlo vacío"),
        parse_mode="Markdown")
    bot.register_next_step_handler(msg, recibir_concepto_gasto)


def recibir_concepto_gasto(message):
    if es_cancelacion(message):
        return
    texto = message.text.strip()
    concepto = "" if texto == "-" else texto[:LIMITE_TEXTO_GASTO]
    datos.setdefault(message.chat.id, {}).setdefault("nuevoGasto", {})["concepto"] = concepto
    msg = bot.send_message(message.chat.id, "💶 ¿Cuánto ha costado? (€)\n\nEjemplo: 145.50",
                           reply_markup=teclado_cancelar("Solo el número, ej: 145.50"))
    bot.register_next_step_handler(msg, recibir_importe_gasto)


def _pedir_numero_gasto(message, siguiente, pregunta, pista):
    """Valida un número y sigue. Se repite tanto en este flujo que tenerlo suelto
    duplicaba seis veces el mismo bloque."""
    if es_cancelacion(message):
        return None
    valor = message.text.replace(",", ".").strip()
    if not _es_numero(valor):
        msg = bot.send_message(message.chat.id, f"🙈 Escribe solo el número. {pista}",
                               reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, siguiente)
        return None
    return float(valor)


def recibir_importe_gasto(message):
    valor = _pedir_numero_gasto(message, recibir_importe_gasto, "", "Ejemplo: 145.50")
    if valor is None:
        return
    chat_id = message.chat.id
    datos[chat_id]["nuevoGasto"]["cost"] = valor
    app_data, _ = _datos_para_calculo(chat_id)
    sugerido = round(_odometro_actual(app_data))
    datos[chat_id]["nuevoGasto"]["_odoSugerido"] = sugerido
    msg = bot.send_message(
        chat_id,
        f"🚗 ¿Con cuántos km se hizo? (el odómetro)\n\n"
        f"Ejemplo: 41500 (el último que conozco es {sugerido} km).\n"
        "Si es un gasto antiguo y no lo sabes, escribe `-` y lo dejamos vacío.",
        reply_markup=teclado_cancelar("km, o - si no lo sabes"), parse_mode="Markdown")
    bot.register_next_step_handler(msg, recibir_odo_gasto)


def recibir_odo_gasto(message):
    if es_cancelacion(message):
        return
    chat_id = message.chat.id
    texto = message.text.replace(",", ".").strip()
    nuevo = datos[chat_id]["nuevoGasto"]
    if texto == "-" or _normalizar_texto(texto).lower() in RESPUESTAS_SIN_FECHA:
        nuevo.pop("odo", None)
    elif _es_numero(texto):
        nuevo["odo"] = float(texto)
    else:
        msg = bot.send_message(chat_id, "🙈 Escribe el número de km, o `-` si no lo sabes.",
                               reply_markup=teclado_cancelar(), parse_mode="Markdown")
        bot.register_next_step_handler(msg, recibir_odo_gasto)
        return
    msg = bot.send_message(
        chat_id,
        "🔁 ¿Cada cuántos MESES se repite?\n\nEjemplo: 12 para el seguro, 24 para la ITV.\n"
        "Escribe 0 si no quieres que te avise.",
        reply_markup=teclado_cancelar("Meses, o 0"))
    bot.register_next_step_handler(msg, recibir_meses_gasto)


def recibir_meses_gasto(message):
    valor = _pedir_numero_gasto(message, recibir_meses_gasto, "", "Ejemplo: 12")
    if valor is None:
        return
    datos[message.chat.id]["nuevoGasto"]["recordarMeses"] = int(valor)
    msg = bot.send_message(
        message.chat.id,
        "🛣️ ¿Y cada cuántos KM?\n\nEjemplo: 15000 para la revisión. Escribe 0 si no aplica.",
        reply_markup=teclado_cancelar("km, o 0"))
    bot.register_next_step_handler(msg, recibir_km_gasto)


def recibir_km_gasto(message):
    valor = _pedir_numero_gasto(message, recibir_km_gasto, "", "Ejemplo: 15000")
    if valor is None:
        return
    datos[message.chat.id]["nuevoGasto"]["recordarKm"] = int(valor)
    mostrar_confirmacion_gasto(message.chat.id)


def mostrar_confirmacion_gasto(chat_id):
    nuevo = datos.get(chat_id, {}).get("nuevoGasto", {})
    tipo = nuevo.get("tipo", "otro")
    aviso = []
    if nuevo.get("recordarMeses"):
        aviso.append(f"cada {nuevo['recordarMeses']} meses")
    if nuevo.get("recordarKm"):
        aviso.append(f"cada {nuevo['recordarKm']} km")
    resumen = (
        "🧾 *Resumen del gasto:*\n\n"
        f"🕐 Fecha: {_formatear_fecha_solo(nuevo.get('fecha'))}\n"
        f"🏷️ Tipo: {TIPOS_GASTO.get(tipo, 'Otros')}\n"
        f"✍️ Concepto: {nuevo.get('concepto') or '—'}\n"
        f"💶 Importe: {round(_num(nuevo.get('cost')), 2)} €\n"
        f"🚗 Odómetro: {round(_num(nuevo['odo'])) if nuevo.get('odo') is not None else 'sin dato'} km\n"
        f"🔔 Avisar: {' y '.join(aviso) if aviso else 'no'}\n\n"
        "¿Guardo este gasto?")
    t = InlineKeyboardMarkup()
    t.add(
        _boton_inline("✅ Guardar", "CG_OK", ESTILO_EXITO),
        _boton_inline("❌ Cancelar", "CG_NO", ESTILO_PELIGRO),
    )
    bot.send_message(chat_id, resumen, reply_markup=t, parse_mode="Markdown")


def _guardar_gasto_confirmado(chat_id):
    estado = datos.get(chat_id, {})
    password = estado.get("password")
    nuevo = estado.get("nuevoGasto", {})

    try:
        app_data, es_nuevo = cargar_datos(password)
    except CryptoJSError:
        mostrar_menu(chat_id, "❌ La contraseña ya no es válida. Vuelve a intentarlo desde el menú.")
        datos.pop(chat_id, None)
        return
    except Exception:
        logger.exception("Error leyendo el backup al guardar el gasto")
        mostrar_menu(chat_id, "⚠️ No he podido guardar el gasto. Avisa al administrador.")
        datos.pop(chat_id, None)
        return

    tipo = nuevo.get("tipo", "otro")
    entrada = {
        "id": str(int(datetime.datetime.now().timestamp() * 1000)),
        # Los gastos son de día, no de hora: la extensión guarda solo YYYY-MM-DD
        # y sumarMeses() cuenta con ello.
        "date": (nuevo.get("fecha") or datetime.date.today().isoformat())[:10],
        "tipo": tipo if tipo in TIPOS_GASTO else "otro",
        "concepto": (nuevo.get("concepto") or "")[:LIMITE_TEXTO_GASTO],
        "cost": _num(nuevo.get("cost")),
        "recordarMeses": int(_num(nuevo.get("recordarMeses"))),
        "recordarKm": int(_num(nuevo.get("recordarKm"))),
        "notas": "",
    }
    # Sin odómetro conocido (gasto antiguo, recibo sin apuntarlo...): se deja sin
    # guardar en vez de forzar un 0, que se confundiría con "0 km" en las gráficas.
    if nuevo.get("odo") is not None:
        entrada["odo"] = _num(nuevo.get("odo"))
    app_data.setdefault("gastos", []).append(entrada)

    try:
        guardar_datos(app_data, password)
    except Exception:
        logger.exception("Error escribiendo el gasto en el backup")
        mostrar_menu(chat_id, "⚠️ No he podido guardar el gasto en el archivo. Avisa al administrador.")
        datos.pop(chat_id, None)
        return

    detalle = (f"🧾 {TIPOS_GASTO.get(entrada['tipo'], 'Otros')}"
               f"{': ' + entrada['concepto'] if entrada['concepto'] else ''}\n"
               f"💶 {round(entrada['cost'], 2)} €")
    resumen = "✅ ¡Gasto guardado!\n\n" + detalle
    if entrada["recordarMeses"] or entrada["recordarKm"]:
        resumen += "\n\n🔔 Te avisaré cuando toque."
    if es_nuevo:
        resumen += "\n\n📁 Se ha creado un archivo nuevo. Usa esta misma contraseña en el dashboard web para verlo."
    datos.pop(chat_id, None)
    mostrar_menu(chat_id, resumen)
    _avisar_a_los_demas(chat_id, detalle)


# =========================================================================
#  AVISOS PROACTIVOS
#  Es lo único que el bot hace mejor que la extensión: el mensaje llega sin
#  que abras nada. La extensión solo avisa si el navegador está abierto.
# =========================================================================
AVISOS_HORA = EV_AVISOS_HORA
AVISOS_DIAS_MARGEN = EV_AVISOS_DIAS
AVISOS_KM_MARGEN = EV_AVISOS_KM
_ultimo_aviso_diario = {}


def _sumar_meses(iso, meses):
    """Suma meses a una fecha ISO sin desbordar el mes (31 ene + 1 mes -> 28 feb)."""
    base = _parse_iso(iso)
    if base is None or not meses:
        return None
    mes = base.month - 1 + int(meses)
    anio = base.year + mes // 12
    mes = mes % 12 + 1
    dia = min(base.day, calendar.monthrange(anio, mes)[1])
    return datetime.datetime(anio, mes, dia)


def _vencimientos(app_data, odo_actual=0, ahora=None):
    """Qué mantenimiento toca, a partir de los gastos con recordatorio.

    Solo cuenta el ÚLTIMO gasto de cada tipo+concepto: si ya has pasado la ITV
    de este año, la del año pasado no debe seguir avisando. El concepto se
    normaliza (sin tildes/mayúsculas/años) para que "ITV" e "ITV 2026" cuenten
    como el mismo aviso: si no, cada renovación anual con un año distinto en el
    texto generaría un aviso duplicado además del correcto. Traducción de
    `vencimientos()` en shared/model.js."""
    ahora = ahora or datetime.datetime.now()
    ultimos = {}
    for g in app_data.get("gastos") or []:
        if not g.get("recordarMeses") and not g.get("recordarKm"):
            continue
        clave = f"{g.get('tipo')}|{_normalizar_concepto_gasto(g.get('concepto'))}"
        previo = ultimos.get(clave)
        if previo is None or str(g.get("date") or "") > str(previo.get("date") or ""):
            ultimos[clave] = g

    salida = []
    for g in ultimos.values():
        fecha = _sumar_meses(g.get("date"), g.get("recordarMeses"))
        dias = round((fecha - ahora).total_seconds() / 86400) if fecha else None
        km_objetivo = (_num(g.get("odo")) + _num(g.get("recordarKm"))) if (g.get("recordarKm") and g.get("odo")) else None
        km = round(km_objetivo - odo_actual) if (km_objetivo and odo_actual) else None
        salida.append({
            "gasto": g, "fecha": fecha, "dias": dias, "km": km,
            "etiqueta": g.get("concepto") or TIPOS_GASTO.get(g.get("tipo"), "Revisión"),
        })

    def urgencia(v):
        # 1000 km ≈ 1 mes, para poder ordenar días y kilómetros en la misma lista.
        por_dias = v["dias"] if v["dias"] is not None else float("inf")
        por_km = v["km"] / 33 if v["km"] is not None else float("inf")
        return min(por_dias, por_km)

    return sorted(salida, key=urgencia)


def _texto_vencimientos(app_data, solo_urgentes=True):
    odo = _odometro_actual(app_data)
    lista = _vencimientos(app_data, odo)
    lineas = []
    for v in lista:
        urge_dias = v["dias"] is not None and v["dias"] <= AVISOS_DIAS_MARGEN
        urge_km = v["km"] is not None and v["km"] <= AVISOS_KM_MARGEN
        if solo_urgentes and not (urge_dias or urge_km):
            continue
        partes = []
        if v["dias"] is not None:
            partes.append("¡vencido!" if v["dias"] < 0 else f"en {v['dias']} días")
        if v["km"] is not None:
            partes.append("pasado de km" if v["km"] < 0 else f"en {v['km']} km")
        icono = "🔴" if (v["dias"] is not None and v["dias"] < 0) or (v["km"] is not None and v["km"] < 0) else "🟡"
        lineas.append(f"{icono} {v['etiqueta']}: {' · '.join(partes)}")
    return lineas


def _texto_luz_hoy(settings):
    """Precio de la luz de hoy y mejor momento para enchufar."""
    precios = _obtener_precios_pvpc(zona=(settings or {}).get("zonaPvpc"))
    if not precios:
        return None
    ahora = datetime.datetime.now()
    actual = _precio_pvpc_hora(precios, ahora.hour)
    horas = precios["horas"]
    media = sum(x["precio"] for x in horas) / len(horas)
    barata = min(horas, key=lambda x: x["precio"])
    cara = max(horas, key=lambda x: x["precio"])
    ventana = _mejor_ventana(precios, 4, ahora.hour)
    lineas = ["💡 *Precio de la luz hoy*", ""]
    if actual is not None:
        nivel = "🟢 barata" if actual <= media * 0.85 else ("🔴 cara" if actual >= media * 1.15 else "🟡 normal")
        lineas.append(f"🕐 Ahora ({ahora.hour:02d}h): *{actual:.4f} €/kWh* — {nivel}")
    lineas += [
        f"📊 Media del día: {media:.4f} €/kWh",
        f"🟢 Más barata: {barata['h']:02d}h a {barata['precio']:.4f}",
        f"🔴 Más cara: {cara['h']:02d}h a {cara['precio']:.4f}",
    ]
    if ventana:
        lineas.append(f"\n🔌 Mejores 4 horas seguidas para cargar: *{ventana['inicio']:02d}–{ventana['fin']:02d}h* "
                      f"({ventana['media']:.4f} €/kWh)")
    if precios["fuente"] != "pvpc":
        lineas.append("\n⚠️ ESIOS no responde: son precios del mercado mayorista, orientativos.")
    return "\n".join(lineas)


@bot.message_handler(commands=["luz"])
def precio_luz_hoy(message):
    if not usuario_autorizado(message.chat.id):
        acceso_denegado(message)
        return
    app_data, _ = _datos_para_calculo(message.chat.id)
    texto = _texto_luz_hoy(app_data.get("settings", {}))
    if texto is None:
        bot.send_message(message.chat.id, "⚠️ No he podido consultar el precio de la luz ahora mismo.")
    else:
        bot.send_message(message.chat.id, texto, parse_mode="Markdown")
    mostrar_menu(message.chat.id)


def _revisar_avisos_diarios():
    """Un mensaje al día, y solo si hay algo que decir."""
    hoy = datetime.date.today().isoformat()
    for chat_id in ALLOWED_USER_IDS:
        if _ultimo_aviso_diario.get(chat_id) == hoy:
            continue
        try:
            app_data, _ = cargar_datos(_password_lista(chat_id))
        except Exception:
            # Archivo cifrado y sin sesión abierta: no se puede mirar y tampoco
            # hay que dar la lata pidiendo la contraseña por iniciativa propia.
            continue

        lineas = _texto_vencimientos(app_data)
        settings = app_data.get("settings", {}) or {}
        if (settings.get("tarifaModo") or "tramos") == "pvpc":
            precios = _obtener_precios_pvpc(zona=settings.get("zonaPvpc"))
            ventana = _mejor_ventana(precios, 4, AVISOS_HORA) if precios else None
            if ventana:
                lineas.append(f"🔌 Hoy lo más barato es de {ventana['inicio']:02d} a {ventana['fin']:02d}h "
                              f"({ventana['media']:.4f} €/kWh)")

        _ultimo_aviso_diario[chat_id] = hoy
        if not lineas:
            continue
        try:
            bot.send_message(chat_id, "🔔 *Buenos días*\n\n" + "\n".join(lineas), parse_mode="Markdown")
        except Exception as exc:
            logger.warning("No se pudo enviar el aviso diario a %s: %s", chat_id, _ocultar_token(exc))


def _iniciar_avisos():
    if AVISOS_HORA is None:
        logger.info("Avisos diarios desactivados (EV_AVISOS_HORA = None)")
        return

    def _bucle():
        while True:
            try:
                if datetime.datetime.now().hour == AVISOS_HORA:
                    _revisar_avisos_diarios()
            except Exception:
                logger.exception("Error en el bucle de avisos")
            # Cada 10 minutos: basta para no perder la hora buena y no gasta nada.
            time.sleep(600)

    hilo = threading.Thread(target=_bucle, daemon=True)
    hilo.start()
    logger.info("Avisos diarios activados a las %02d:00", AVISOS_HORA)


@bot.message_handler(commands=["verobd"])
@bot.message_handler(func=lambda m: m.text == BTN_VER_OBD)
def ver_obd_inicio(message):
    datos[message.chat.id] = {}
    _requiere_password(message, mostrar_ultimos_obd)


def _reintentar_ver_obd(message):
    if es_cancelacion(message):
        return
    chat_id = message.chat.id
    if _password_bloqueada(chat_id):
        mostrar_menu(chat_id, f"🚫 Demasiados intentos fallidos. Espera {_minutos_restantes_bloqueo(chat_id)} min. antes de volver a intentarlo.")
        datos.pop(chat_id, None)
        return
    password = message.text.strip()
    _intentar_borrar_mensaje(message)
    mostrar_ultimos_obd(message, password)


def mostrar_ultimos_obd(message, password):
    chat_id = message.chat.id
    try:
        app_data, _ = cargar_datos(password)
    except CryptoJSError:
        _registrar_intento_fallido(chat_id)
        msg = bot.send_message(chat_id, "❌ Contraseña incorrecta. Inténtalo de nuevo o pulsa Cancelar.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, _reintentar_ver_obd)
        return
    except Exception:
        logger.exception("Error leyendo el backup para ver OBD")
        mostrar_menu(chat_id, "⚠️ No he podido leer el archivo del dashboard.")
        datos.pop(chat_id, None)
        return

    _limpiar_intentos(chat_id)
    datos.pop(chat_id, None)
    obd = app_data.get("obd", [])
    if not obd:
        mostrar_menu(chat_id, "📭 Todavía no hay registros de batería.")
        return

    ultimos = sorted(obd, key=lambda o: o.get("date", ""), reverse=True)[:5]
    lineas = [f"🔎 *Últimas {len(ultimos)} lecturas de batería*"]
    for o in ultimos:
        lineas.append("")
        lineas.append(f"*{_fecha_corta(o.get('date'))}*")
        lineas.append(f"🔋 SoH {o.get('soh', 0)}%   🚗 {o.get('odo', 0)} km")
        if o.get("cap"):
            lineas.append(f"🔢 {o.get('cap')} kWh útiles")
    bot.send_message(chat_id, "\n".join(lineas), parse_mode="Markdown")
    mostrar_menu(chat_id)


# =========================================================================
# Editar / Borrar registros ya guardados (cargas y OBD) mediante botones inline
# =========================================================================

def teclado_gestion_root():
    t = InlineKeyboardMarkup()
    t.add(InlineKeyboardButton("🔌 Cargas", callback_data="gm_logs"))
    t.add(InlineKeyboardButton("🔋 Batería (OBD)", callback_data="gm_obd"))
    t.add(InlineKeyboardButton("🧾 Gastos", callback_data="gm_gastos"))
    t.add(InlineKeyboardButton("❌ Cerrar", callback_data="gm_close"))
    return t


@bot.message_handler(commands=["gestionar"])
@bot.message_handler(func=lambda m: m.text == BTN_GESTIONAR)
def gestionar_inicio(message):
    datos[message.chat.id] = {}
    _requiere_password(message, mostrar_menu_gestion)


def mostrar_menu_gestion(message, password):
    bot.send_message(message.chat.id, "🗂️ ¿Qué quieres gestionar?", reply_markup=teclado_gestion_root())


# =========================================================================
# "Más opciones": resumen de ahorro, configuración, tarifas, exportar/importar
# =========================================================================

# Cada campo: clave -> (etiqueta corta, tipo "num"/"text"/"choice", unidad).
# La etiqueta va corta y la unidad separada porque en la pantalla de configuración el valor
# actual se pinta DENTRO del propio botón ("🔋 Capacidad: 50 kWh"); con etiquetas largas
# Telegram recortaría el texto en el móvil y no se vería el valor, que es lo importante.
#
# Ojo con priceEV / priceICE: son los precios de COMPRA de los dos coches (lo que costó el
# eléctrico y lo que habría costado el de combustión equivalente), no precios de energía. Se
# usan solo para calcular cuánto falta para amortizar el sobreprecio. Antes se llamaban
# "Precio eléctrico" y "Precio gasolina" y se confundían con el precio del kWh y del litro.
CONFIG_CAMPOS = {
    "model": ("🚘 Modelo", "text", ""),
    "capacity": ("🔋 Capacidad", "num", " kWh"),
    "wltp": ("🛣️ Autonomía WLTP", "num", " km"),
    "efficiency": ("⚡ Eficiencia", "num", " %"),
    "homePower": ("🔌 Cargador de casa", "num", " kW"),
    "tarifaModo": ("💡 Tarifa", "choice", ""),
    "tarifaP1": ("☀️ Precio punta", "num", " €/kWh"),
    "tarifaP2": ("🌤️ Precio llano", "num", " €/kWh"),
    "tarifaP3": ("🌙 Precio valle", "num", " €/kWh"),
    "tarifaHoraPunta": ("🕗 Empieza la punta", "num", " h"),
    "tarifaHoraValle": ("🕙 Vuelve el valle", "num", " h"),
    "tarifaFijo": ("💡 Precio del kWh", "num", " €/kWh"),
    "costeFijoMes": ("🧾 Fijo mensual luz", "num", " €"),
    "iceModel": ("🚗 Coche referencia", "text", ""),
    "iceFuel": ("⛽ Combustible", "choice", ""),
    "iceLiters": ("💨 Consumo referencia", "num", " L/100km"),
    "icePrice": ("💶 Precio del litro", "num", " €"),
    "priceEV": ("💰 Compra eléctrico", "num", " €"),
    "priceICE": ("💰 Compra referencia", "num", " €"),
    "city": ("📍 Ciudad", "text", ""),
    "provincia": ("🗺️ Provincia", "text", ""),
}

# Campos de tipo "choice": valor guardado -> texto que ve el usuario.
CONFIG_OPCIONES = {
    "iceFuel": {clave: nombre for clave, (nombre, _campo) in CARBURANTES.items()},
    "tarifaModo": {
        "tramos": "3 tramos (2.0TD)",
        "dos": "2 tramos punta/valle",
        "fijo": "Precio fijo",
        "pvpc": "Regulado (PVPC)",
    },
}

# Valor que se asume cuando un campo "choice" está vacío en el archivo.
CONFIG_VALOR_POR_DEFECTO = {
    "iceFuel": CARBURANTE_POR_DEFECTO,
    "tarifaModo": "tramos",
}

# Campos de tarifa que solo tienen sentido con ciertos modos: si no, el menú de
# configuración se llena de opciones que no hacen nada.
CONFIG_CAMPOS_POR_MODO = {
    "tarifaP1": ("tramos", "dos"),
    "tarifaP2": ("tramos",),
    "tarifaP3": ("tramos", "dos"),
    "tarifaHoraPunta": ("dos",),
    "tarifaHoraValle": ("dos",),
    "tarifaFijo": ("fijo",),
}

# Fichas de coches para no tener que escribir capacidad, WLTP y demás a mano. No hay ninguna API
# pública gratuita seria con capacidad útil de batería y WLTP europeo (las que existen, tipo vPIC,
# son del mercado de EE.UU. y no traen ni una cosa ni la otra), así que la alternativa honesta es
# una tabla corta y revisable aquí, con la fuente anotada, en vez de inventar datos.
MODELOS_CONOCIDOS = {
    "mokka-e": {
        "nombre": "Opel Mokka-e (2021)",
        "settings": {
            "model": "Opel Mokka-e",
            "capacity": 46,
            "wltp": 332,
            "iceModel": "Opel Mokka 1.2 Turbo 130",
            "iceFuel": "gasolina95",
            "iceLiters": 6.2,
        },
        "nota": (
            "🔋 50 kWh brutos / 46 útiles y 332 km WLTP.\n\n"
            "⚠️ El consumo de 6,2 L/100km del Mokka gasolina es una ESTIMACIÓN: no he "
            "encontrado una ficha oficial que lo confirme. Míralo en la ficha técnica y "
            "corrígelo aquí mismo si no cuadra: de ese número dependen todos tus ahorros."
        ),
    },
}


def teclado_modelos():
    t = InlineKeyboardMarkup()
    for clave, ficha in MODELOS_CONOCIDOS.items():
        t.add(InlineKeyboardButton(f"🚘 {ficha['nombre']}", callback_data=f"mdl|{clave}"))
    t.add(InlineKeyboardButton("⬅️ Volver", callback_data="mo_config"))
    return t


def teclado_mas_opciones(chat_id=None):
    t = InlineKeyboardMarkup()
    t.add(InlineKeyboardButton("📈 Resumen y ahorro", callback_data="mo_resumen"))
    t.add(InlineKeyboardButton("📊 Estadísticas", callback_data="mo_stats"))
    t.add(InlineKeyboardButton("⚙️ Configuración", callback_data="mo_config"))
    t.add(InlineKeyboardButton("🏷️ Tarifa 2.0TD típica", callback_data="mo_preset_iberdrola"))
    t.add(InlineKeyboardButton("⛽ Actualizar precio del litro", callback_data="mo_gasoil"))
    t.add(InlineKeyboardButton("📤 Exportar backup", callback_data="mo_exportar"))
    t.add(InlineKeyboardButton("📥 Cómo importar", callback_data="mo_importar_info"))
    # Solo tiene sentido si hay algo que olvidar: con EV_BACKUP_PASSWORD fija en config.py el bot
    # nunca pregunta, así que el botón confundiría.
    if chat_id is not None and not EV_BACKUP_PASSWORD and chat_id in _passwords_recordadas:
        t.add(_boton_inline("🔒 Olvidar contraseña", "mo_olvidar", ESTILO_PELIGRO))
    t.add(InlineKeyboardButton("❌ Cerrar", callback_data="gm_close"))
    return t


@bot.message_handler(commands=["masopciones"])
@bot.message_handler(func=lambda m: m.text == BTN_MAS)
def mas_opciones_inicio(message):
    datos[message.chat.id] = {}
    _requiere_password(message, mostrar_menu_mas_opciones)


def mostrar_menu_mas_opciones(message, password):
    chat_id = message.chat.id
    bot.send_message(chat_id, "⚙️ ¿Qué quieres hacer?", reply_markup=teclado_mas_opciones(chat_id))


def _total_gastos(app_data, anio=None):
    """Suma de los gastos que no son recargas (mantenimiento, ITV, seguro...).

    Los da de alta el panel de la extensión; el bot no los edita, pero tiene que
    contarlos o enseñaría un €/km más barato de lo que es en realidad."""
    total = 0.0
    for g in app_data.get("gastos", []) or []:
        if anio is not None and str(g.get("date", ""))[:4] != str(anio):
            continue
        total += _num(g.get("cost"), 0)
    return total


def mostrar_resumen(chat_id, app_data):
    settings = app_data.get("settings", {})
    logs = app_data.get("logs", [])
    obd = app_data.get("obd", [])

    total_kwh = sum(l.get("kwh", 0) for l in logs)
    total_coste_ev = sum(l.get("cost", 0) for l in logs)
    total_gastos = _total_gastos(app_data)
    total_km = sum(_num(l.get("km"), 0) for l in logs)

    ice_liters = settings.get("iceLiters", 0) or 0
    # Usamos el precio real y actual del carburante (API oficial, por provincia si está configurada
    # en ⚙️ Configuración) para no depender de que el usuario lo busque y lo actualice a mano;
    # si falla, o si lo ha puesto a mano a propósito, caemos al valor configurado.
    ice_price, fuente_carburante = _precio_carburante_efectivo(settings)
    nota_precio_gasoil = f"⛽ {_nombre_carburante(settings)}: {ice_price} €/L\n_({fuente_carburante})_"
    coste_ice_equivalente = sum(
        l.get("iceCost") if l.get("iceCost") else (l.get("km", 0) / 100) * ice_liters * ice_price
        for l in logs
    )
    ahorro = coste_ice_equivalente - total_coste_ev

    precio_ev = settings.get("priceEV", 0) or 0
    precio_ice = settings.get("priceICE", 0) or 0
    sobreprecio = precio_ev - precio_ice
    roi = (ahorro / sobreprecio * 100) if sobreprecio > 0 else 100

    soh_actual = None
    if obd:
        ultimo_obd = sorted(obd, key=lambda o: o.get("date", ""))[-1]
        soh_actual = ultimo_obd.get("soh")
    soh_texto = f"{soh_actual}%" if soh_actual is not None else "Sin datos"

    wltp = settings.get("wltp", 0) or 0
    efficiency = settings.get("efficiency", 100) or 100
    soh_para_autonomia = soh_actual if soh_actual is not None else 100
    autonomia_real = wltp * (soh_para_autonomia / 100) * (efficiency / 100)

    lineas = [
        "📈 *Resumen*",
        "",
        "*Cargas*",
        f"🔋 {round(total_kwh, 2)} kWh en {len(logs)} cargas",
        f"💶 Gastado: {round(total_coste_ev, 2)} €",
        "",
        "*Frente a gasolina*",
        f"⛽ Habría costado: {round(coste_ice_equivalente, 2)} €",
        f"💰 Ahorro: {round(ahorro, 2)} €",
        f"📊 ROI del sobreprecio: {round(roi, 1)} %",
    ]
    # Los gastos de mantenimiento, ITV, seguro y demás se anotan en el panel de la
    # extensión. Si no se cuentan aquí, el coste por km sale más bajo de lo real.
    if total_gastos or total_km:
        lineas += ["", "*Coste total del coche*"]
        if total_gastos:
            lineas.append(f"🧾 Otros gastos: {round(total_gastos, 2)} €")
        if total_km:
            coste_km = (total_coste_ev + total_gastos) / total_km
            lineas.append(f"🚗 {round(total_km)} km · {round(coste_km, 3)} €/km")
    pendientes = _texto_vencimientos(app_data, solo_urgentes=False)
    if pendientes:
        lineas += ["", "*Próximo mantenimiento*"] + pendientes[:4]
    lineas += [
        "",
        "*Batería*",
        f"🔋 Salud (SoH): {soh_texto}",
        f"🚗 Autonomía real: {round(autonomia_real)} km",
        "",
        nota_precio_gasoil,
    ]
    bot.send_message(chat_id, "\n".join(lineas), parse_mode="Markdown")


def _texto_ahorro_carga(app_data, coste_ev, km):
    """Ahorro de UNA carga concreta frente al coche de referencia de combustión, usando el consumo
    (L/100km) configurado y el precio real y actual del carburante (por provincia si está
    configurada), igual criterio que el resumen global. Devuelve '' si no hay km para comparar."""
    if not km:
        return ""
    settings = app_data.get("settings", {})
    ice_liters = settings.get("iceLiters", 0) or 0
    ice_price, _ = _precio_carburante_efectivo(settings)
    coste_ice = (km / 100) * ice_liters * ice_price
    ahorro = coste_ice - coste_ev
    return (
        f"\n\n💚 *Ahorro de esta carga: ~{round(ahorro, 2)} €*\n"
        f"Con {_nombre_carburante(settings)}, esos {km} km\n"
        f"habrían costado ~{round(coste_ice, 2)} €."
    )


def _resumen_logs_por_anio(logs):
    por_anio = {}
    for l in logs:
        fecha = l.get("date") or ""
        anio = fecha[:4] if len(fecha) >= 4 else "?"
        d = por_anio.setdefault(anio, {"kwh": 0.0, "km": 0.0, "cost": 0.0, "home_kwh": 0.0, "street_kwh": 0.0})
        d["kwh"] += l.get("kwh", 0) or 0
        d["km"] += l.get("km", 0) or 0
        d["cost"] += l.get("cost", 0) or 0
        if l.get("type") == "home":
            d["home_kwh"] += l.get("kwh", 0) or 0
        else:
            d["street_kwh"] += l.get("kwh", 0) or 0
    return por_anio


def mostrar_estadisticas_avanzadas(chat_id, app_data):
    settings = app_data.get("settings", {})
    logs = app_data.get("logs", [])
    if not logs:
        bot.send_message(chat_id, "📭 Todavía no hay cargas guardadas para calcular estadísticas.")
        return

    ice_liters = settings.get("iceLiters", 0) or 0
    ice_price, fuente_carburante = _precio_carburante_efectivo(settings)
    nombre_carburante = _nombre_carburante(settings)

    # --- Uso y coste por año, con mix casa/calle ---
    por_anio = _resumen_logs_por_anio(logs)
    lineas_anio = ["📊 *Uso y coste por año*"]
    for anio in sorted(por_anio.keys()):
        d = por_anio[anio]
        coste_diesel_equiv = (d["km"] / 100) * ice_liters * ice_price if d["km"] else 0
        ahorro_anio = coste_diesel_equiv - d["cost"]
        gastos_anio = _total_gastos(app_data, anio)
        lineas_anio.append("")
        lineas_anio.append(f"*{anio}*")
        lineas_anio.append(f"🔋 {round(d['kwh'], 1)} kWh   🚗 {round(d['km'])} km")
        lineas_anio.append(f"💶 {round(d['cost'], 2)} €   💰 ahorro {round(ahorro_anio, 2)} €")
        if gastos_anio:
            lineas_anio.append(f"🧾 Otros gastos: {round(gastos_anio, 2)} €")
        lineas_anio.append(f"🏠 {round(d['home_kwh'], 1)} kWh   🛣️ {round(d['street_kwh'], 1)} kWh")
    bot.send_message(chat_id, "\n".join(lineas_anio), parse_mode="Markdown")

    # --- Coste real €/100km vs diésel ---
    total_km = sum(l.get("km", 0) or 0 for l in logs)
    total_cost = sum(l.get("cost", 0) or 0 for l in logs)
    total_gastos = _total_gastos(app_data)
    coste_100km_ev = (total_cost / total_km * 100) if total_km else None
    coste_100km_diesel = ice_liters * ice_price
    lineas_extra = ["⛽ *Coste real por 100 km*", ""]
    if coste_100km_ev is not None:
        lineas_extra.append(f"⚡ Eléctrico: {round(coste_100km_ev, 2)} €")
    else:
        lineas_extra.append("⚡ Eléctrico: aún sin km suficientes")
    lineas_extra.append(f"⛽ {nombre_carburante}: {round(coste_100km_diesel, 2)} €")
    lineas_extra.append(f"_{ice_price} €/L_")
    lineas_extra.append(f"_{fuente_carburante}_")
    if total_gastos and total_km:
        # Mismo criterio que el KPI "coste por km" del panel: recargas + gastos.
        lineas_extra += [
            "",
            f"🧾 Con mantenimiento y demás: {round((total_cost + total_gastos) / total_km * 100, 2)} €",
            f"_Incluye {round(total_gastos, 2)} € de otros gastos._",
        ]

    # --- Zona dulce de carga (20-80%) ---
    con_ambos = [l for l in logs if l.get("socStart") is not None and l.get("socEnd") is not None]
    en_zona = [l for l in con_ambos if l["socStart"] >= 20 and l["socEnd"] <= 80]
    lineas_extra += ["", "🔋 *Zona dulce (20-80%)*", ""]
    if con_ambos:
        pct_zona = len(en_zona) / len(con_ambos) * 100
        lineas_extra.append(f"{round(pct_zona)}% de tus cargas")
        lineas_extra.append(f"({len(en_zona)} de {len(con_ambos)}) se quedan dentro.")
    else:
        lineas_extra.append("Aún sin cargas con % inicial y final.")

    # --- Operadores públicos: nº de cargas y €/kWh real ---
    calle_logs = [l for l in logs if l.get("type") == "street"]
    lineas_extra += ["", "🏷️ *Operadores públicos*"]
    if calle_logs:
        conteo = {}
        acumulado = {}
        for l in calle_logs:
            marca = l.get("brand") or "Otros"
            conteo[marca] = conteo.get(marca, 0) + 1
            acc = acumulado.setdefault(marca, {"kwh": 0.0, "cost": 0.0})
            acc["kwh"] += l.get("kwh", 0) or 0
            acc["cost"] += (l.get("cost", 0) or 0) + (l.get("subCost", 0) or 0)
        lineas_extra += ["", "Más usados:"]
        for marca, n in sorted(conteo.items(), key=lambda kv: kv[1], reverse=True)[:5]:
            lineas_extra.append(f"• {_escapar_markdown(marca)}: {n}")
        lineas_extra += ["", "Más baratos (€/kWh real):"]
        ranking_precio = sorted(
            ((marca, acc["cost"] / acc["kwh"]) for marca, acc in acumulado.items() if acc["kwh"] > 0),
            key=lambda kv: kv[1],
        )
        for marca, precio in ranking_precio[:5]:
            lineas_extra.append(f"• {_escapar_markdown(marca)}: {round(precio, 3)} €")
    else:
        lineas_extra += ["", "Aún sin cargas en la calle."]

    bot.send_message(chat_id, "\n".join(lineas_extra), parse_mode="Markdown")


def mostrar_configuracion(chat_id, app_data):
    """Un solo mensaje: antes se enviaba la lista de valores COMO TEXTO y además otro mensaje
    con un botón por campo repitiendo las mismas etiquetas, lo que obligaba a hacer el doble de
    scroll en el móvil para ver lo mismo dos veces. Ahora el valor actual va dentro del botón."""
    settings = app_data.get("settings", {})
    auto_precio = settings.get("icePriceAuto") is not False
    modo_tarifa = settings.get("tarifaModo") or "tramos"
    t = InlineKeyboardMarkup()
    for clave, (etiqueta, tipo, unidad) in CONFIG_CAMPOS.items():
        # Con tarifa fija no pinta nada preguntar por el precio del valle, y al revés.
        modos = CONFIG_CAMPOS_POR_MODO.get(clave)
        if modos and modo_tarifa not in modos:
            continue
        valor = settings.get(clave)
        if tipo == "choice":
            # Se guarda una clave interna ("gasolina95"), pero al usuario hay que enseñarle
            # el nombre de verdad ("Gasolina 95").
            opciones = CONFIG_OPCIONES.get(clave, {})
            texto_valor = opciones.get(valor) or opciones.get(CONFIG_VALOR_POR_DEFECTO.get(clave), "— sin definir")
        elif valor in (None, ""):
            texto_valor = "— sin definir"
        else:
            # Un valor de texto largo (p.ej. el modelo del coche) desbordaría el botón y
            # Telegram lo recortaría por su cuenta, escondiendo la unidad.
            texto_valor = str(valor)
            if len(texto_valor) > 16:
                texto_valor = texto_valor[:15] + "…"
            texto_valor = f"{texto_valor}{unidad}"
        # El precio del litro se consulta solo a la API oficial, así que hay que dejar claro
        # si el número que se ve manda o si es solo el último valor guardado.
        if clave == "icePrice":
            texto_valor += " (auto)" if auto_precio else " (a mano)"
        t.add(InlineKeyboardButton(f"{etiqueta}: {texto_valor}", callback_data=f"cfg|{clave}"))
    t.add(InlineKeyboardButton("🚘 Cargar datos de un modelo", callback_data="mo_modelos"))
    t.add(InlineKeyboardButton("⬅️ Volver", callback_data="mo_back"))
    bot.send_message(
        chat_id,
        "⚙️ *Configuración*\n\nPulsa un campo para cambiarlo 👇",
        parse_mode="Markdown",
        reply_markup=t,
    )


def _iniciar_edicion_config(chat_id, clave, password):
    if clave not in CONFIG_CAMPOS:
        bot.send_message(chat_id, "⚠️ Campo no reconocido.")
        return
    etiqueta, tipo = CONFIG_CAMPOS[clave][0], CONFIG_CAMPOS[clave][1]
    _set_password_sesion(chat_id, password)
    if tipo == "choice":
        # Un campo con dos valores posibles no se escribe a mano: se pulsa. Escribirlo solo
        # daría ocasión de escribirlo mal.
        t = InlineKeyboardMarkup()
        for valor, nombre in CONFIG_OPCIONES.get(clave, {}).items():
            t.add(InlineKeyboardButton(nombre, callback_data=f"cfgset|{clave}|{valor}"))
        t.add(InlineKeyboardButton("⬅️ Volver", callback_data="mo_config"))
        bot.send_message(chat_id, f"✏️ *{etiqueta}*\n\nElige una opción 👇", parse_mode="Markdown", reply_markup=t)
        return
    datos.setdefault(chat_id, {})["editConfig"] = clave
    datos[chat_id]["editConfigTipo"] = tipo
    aviso = ""
    if clave == "icePrice":
        aviso = (
            "\n\n⚠️ Si lo pones a mano dejaré de actualizarlo solo desde la API oficial.\n"
            "Para volver al automático usa '⛽ Actualizar precio del litro' en Más opciones."
        )
    ejemplo = "Madrid" if tipo == "text" else "0.22"
    msg = bot.send_message(
        chat_id,
        f"✏️ *{etiqueta}*\n\nEscribe el nuevo valor.\nEjemplo: {ejemplo}{aviso}",
        parse_mode="Markdown",
        reply_markup=teclado_cancelar(f"Ejemplo: {ejemplo}"),
    )
    bot.register_next_step_handler(msg, recibir_valor_config)


def recibir_valor_config(message):
    if es_cancelacion(message):
        return
    chat_id = message.chat.id
    estado = datos.get(chat_id, {})
    clave = estado.get("editConfig")
    tipo = estado.get("editConfigTipo", "num")
    password = estado.get("password")
    if not clave:
        mostrar_menu(chat_id, "⚠️ La edición ha caducado. Vuelve a intentarlo desde '⚙️ Más opciones'.")
        datos.pop(chat_id, None)
        return
    if tipo == "text":
        valor_final = message.text.strip().replace("\n", " ")[:60]
        if not valor_final:
            msg = bot.send_message(chat_id, "🙈 Escribe un texto, no puede estar vacío.", reply_markup=teclado_cancelar())
            bot.register_next_step_handler(msg, recibir_valor_config)
            return
    else:
        valor_txt = message.text.replace(',', '.').strip()
        if not _es_numero(valor_txt):
            msg = bot.send_message(chat_id, "🙈 Escribe solo un número, por ejemplo: 0.22", reply_markup=teclado_cancelar())
            bot.register_next_step_handler(msg, recibir_valor_config)
            return
        valor_final = float(valor_txt)
    try:
        app_data, _ = cargar_datos(password)
    except CryptoJSError:
        mostrar_menu(chat_id, "❌ La contraseña ya no es válida. Vuelve a intentarlo desde el menú.")
        datos.pop(chat_id, None)
        return
    except Exception:
        logger.exception("Error leyendo el backup al editar configuración")
        mostrar_menu(chat_id, "⚠️ No se pudo guardar el cambio.")
        datos.pop(chat_id, None)
        return
    app_data.setdefault("settings", {})[clave] = valor_final
    # Poner el precio del litro a mano significa "no me lo toques": deja de sobrescribirse con
    # el de la API hasta que el usuario pulse "Actualizar gasóleo".
    if clave == "icePrice":
        app_data["settings"]["icePriceAuto"] = False
    _sincronizar_tarifa(app_data["settings"], clave)
    # La extensión usa "ciudad" y el bot usaba "city": se guardan las dos para
    # que quien lea primero encuentre siempre el mismo sitio.
    if clave in ("city", "ciudad"):
        app_data["settings"]["city"] = valor_final
        app_data["settings"]["ciudad"] = valor_final
    try:
        guardar_datos(app_data, password)
    except Exception:
        logger.exception("Error guardando configuración")
        mostrar_menu(chat_id, "⚠️ No se pudo guardar el cambio en el archivo.")
        datos.pop(chat_id, None)
        return
    datos.pop(chat_id, None)
    etiqueta = CONFIG_CAMPOS.get(clave, (clave, "num", ""))[0]
    mostrar_menu(chat_id, f"✅ {etiqueta} actualizado a {valor_final}.")


def exportar_backup(chat_id):
    if not os.path.exists(EV_BACKUP_PATH):
        bot.send_message(chat_id, "📭 Todavía no hay ningún backup guardado.")
        return
    try:
        with open(EV_BACKUP_PATH, "rb") as f:
            bot.send_document(
                chat_id, f, visible_file_name="ev_backup.json",
                caption="📤 Aquí tienes tu backup. Si está cifrado, solo se podrá abrir con la contraseña correcta.",
            )
    except Exception:
        logger.exception("Error exportando el backup")
        bot.send_message(chat_id, "⚠️ No se pudo exportar el backup.")


@bot.message_handler(content_types=['document'])
def recibir_documento_importar(message):
    chat_id = message.chat.id
    if not usuario_autorizado(chat_id):
        return
    doc = message.document
    nombre = (doc.file_name or "").lower()
    if not nombre.endswith(".json"):
        bot.send_message(chat_id, "⚠️ Solo puedo importar archivos .json de backup (usa '📥 Cómo importar backup' en Más opciones).")
        return
    try:
        info = bot.get_file(doc.file_id)
        contenido = bot.download_file(info.file_path)
        nuevo_json = json.loads(contenido.decode("utf-8"))
    except Exception:
        logger.exception("Error leyendo el archivo importado")
        bot.send_message(chat_id, "❌ Ese archivo no es un JSON válido.")
        return

    if not isinstance(nuevo_json, dict) or not (
        "isEncrypted" in nuevo_json or "settings" in nuevo_json or "logs" in nuevo_json
    ):
        bot.send_message(chat_id, "❌ Ese archivo no tiene el formato esperado de backup.")
        return

    datos.setdefault(chat_id, {})["_import_pendiente"] = nuevo_json
    t = InlineKeyboardMarkup()
    t.add(
        _boton_inline("✅ Sí, reemplazar", "imp_ok", ESTILO_PELIGRO),
        _boton_inline("❌ No", "imp_no"),
    )
    bot.send_message(
        chat_id,
        "⚠️ Esto reemplazará TODOS los datos actuales del backup por los de este archivo.\n\n"
        "Se guardará antes una copia de seguridad del backup actual, por si acaso.\n\n"
        "¿Seguro que quieres continuar?",
        reply_markup=t,
    )


def _listar_logs_inline(chat_id, app_data):
    logs = sorted(app_data.get("logs", []), key=lambda l: l.get("date", ""), reverse=True)[:8]
    if not logs:
        bot.send_message(chat_id, "📭 No hay cargas guardadas.")
        return
    t = InlineKeyboardMarkup()
    for l in logs:
        lugar = "🏠" if l.get("type") == "home" else "🛣️"
        if l.get("pendingFinal"):
            etiqueta = f"{lugar} {l.get('date', '?')} · ⏳ sin cerrar"
        else:
            etiqueta = f"{lugar} {l.get('date', '?')} · {l.get('kwh', 0)}kWh · {l.get('cost', 0)}€"
        t.add(InlineKeyboardButton(etiqueta, callback_data=f"L|{l.get('id')}"))
    t.add(InlineKeyboardButton("⬅️ Volver", callback_data="gm_back"))
    bot.send_message(chat_id, "🔌 Selecciona una carga para editar o borrar:", reply_markup=t)


def _listar_obd_inline(chat_id, app_data):
    obd = sorted(app_data.get("obd", []), key=lambda o: o.get("date", ""), reverse=True)[:8]
    if not obd:
        bot.send_message(chat_id, "📭 No hay registros de batería.")
        return
    t = InlineKeyboardMarkup()
    for o in obd:
        etiqueta = f"🔋 {o.get('date', '?')} · SoH {o.get('soh', 0)}%"
        t.add(InlineKeyboardButton(etiqueta, callback_data=f"O|{o.get('id')}"))
    t.add(InlineKeyboardButton("⬅️ Volver", callback_data="gm_back"))
    bot.send_message(chat_id, "🔋 Selecciona un registro para editar o borrar:", reply_markup=t)


def _listar_gastos_inline(chat_id, app_data):
    gastos = sorted(app_data.get("gastos", []), key=lambda g: g.get("date", ""), reverse=True)[:8]
    if not gastos:
        bot.send_message(chat_id, "📭 Todavía no has anotado ningún gasto.")
        return
    t = InlineKeyboardMarkup()
    for g in gastos:
        nombre = g.get("concepto") or TIPOS_GASTO.get(g.get("tipo"), "Otros")
        t.add(InlineKeyboardButton(f"🧾 {g.get('date', '?')} · {nombre} · {round(_num(g.get('cost')), 2)} €",
                                   callback_data=f"X|{g.get('id')}"))
    t.add(InlineKeyboardButton("⬅️ Volver", callback_data="gm_back"))
    bot.send_message(chat_id, "🧾 Selecciona un gasto para borrarlo:", reply_markup=t)


def _confirmar_borrado_gasto(chat_id, gasto_id):
    t = InlineKeyboardMarkup()
    t.add(
        _boton_inline("✅ Sí, borrar", f"XDY|{gasto_id}", ESTILO_PELIGRO),
        _boton_inline("❌ No", "gm_gastos"),
    )
    bot.send_message(chat_id, "🗑️ ¿Seguro que borro este gasto? No se puede deshacer.", reply_markup=t)


def _opciones_log(chat_id, log_id):
    t = InlineKeyboardMarkup()
    t.add(
        InlineKeyboardButton("✏️ Editar", callback_data=f"LE|{log_id}"),
        InlineKeyboardButton("🗑️ Borrar", callback_data=f"LD|{log_id}"),
    )
    t.add(InlineKeyboardButton("⬅️ Volver", callback_data="gm_logs"))
    bot.send_message(chat_id, "¿Qué quieres hacer con esta carga?", reply_markup=t)


def _opciones_obd(chat_id, obd_id):
    t = InlineKeyboardMarkup()
    t.add(
        InlineKeyboardButton("✏️ Editar", callback_data=f"OE|{obd_id}"),
        InlineKeyboardButton("🗑️ Borrar", callback_data=f"OD|{obd_id}"),
    )
    t.add(InlineKeyboardButton("⬅️ Volver", callback_data="gm_obd"))
    bot.send_message(chat_id, "¿Qué quieres hacer con este registro?", reply_markup=t)


def _confirmar_borrado_log(chat_id, log_id):
    t = InlineKeyboardMarkup()
    t.add(
        _boton_inline("✅ Sí, borrar", f"LDY|{log_id}", ESTILO_PELIGRO),
        _boton_inline("❌ No", f"L|{log_id}"),
    )
    bot.send_message(chat_id, "⚠️ ¿Seguro que quieres borrar esta carga? No se puede deshacer.", reply_markup=t)


def _confirmar_borrado_obd(chat_id, obd_id):
    t = InlineKeyboardMarkup()
    t.add(
        _boton_inline("✅ Sí, borrar", f"ODY|{obd_id}", ESTILO_PELIGRO),
        _boton_inline("❌ No", f"O|{obd_id}"),
    )
    bot.send_message(chat_id, "⚠️ ¿Seguro que quieres borrar este registro? No se puede deshacer.", reply_markup=t)


@bot.callback_query_handler(func=lambda call: True)
def manejar_callback_gestion(call):
    chat_id = call.message.chat.id
    data = call.data
    bot.answer_callback_query(call.id)

    if not usuario_autorizado(chat_id):
        bot.send_message(chat_id, "🚫 No tienes permiso para usar este bot.")
        return

    # Cualquier pulsación de botón cuenta como actividad: refresca la marca de tiempo de la
    # sesión para que el purgador de sesiones abandonadas no la borre mientras el usuario
    # sigue interactuando (p.ej. navegando los menús de campos avanzados).
    estado_sesion = datos.get(chat_id)
    if estado_sesion is not None and "password" in estado_sesion:
        estado_sesion["_ts"] = datetime.datetime.now()

    if data == "gm_close":
        datos.pop(chat_id, None)
        bot.send_message(chat_id, "Cerrado. Usa el menú para seguir.")
        return

    # --- Confirmaciones que no necesitan tener el archivo ya cargado ---
    if data == "CL_NO":
        datos.pop(chat_id, None)
        mostrar_menu(chat_id, "Vale, no he guardado la carga. 😊")
        return
    if data == "CO_NO":
        datos.pop(chat_id, None)
        mostrar_menu(chat_id, "Vale, no he guardado el registro. 😊")
        return
    if data == "CL_OK":
        _guardar_carga_confirmada(chat_id)
        return
    if data == "CL_FECHA":
        nueva = datos.get(chat_id, {}).get("nuevaCarga", {})
        iniciar_selector_fecha_hora(chat_id, "H_INI_EDIT", nueva.get("fechaInicio"))
        return
    if data == "CL_FECHA_INI":
        nueva = datos.get(chat_id, {}).get("nuevaCarga", {})
        iniciar_selector_fecha_hora(chat_id, "S_INI_EDIT", nueva.get("fechaInicio"))
        return
    if data == "CL_FECHA_FIN":
        nueva = datos.get(chat_id, {}).get("nuevaCarga", {})
        iniciar_selector_fecha_hora(chat_id, "S_FIN_EDIT", nueva.get("fechaFin"))
        return
    if data == "CL_FIN_CASA":
        nueva = datos.get(chat_id, {}).get("nuevaCarga", {})
        iniciar_selector_fecha_hora(chat_id, "H_FIN_NUEVA", nueva.get("fechaFin"))
        return
    if data == "CO_OK":
        _guardar_obd_confirmado(chat_id)
        return
    if data == "CG_NO":
        datos.pop(chat_id, None)
        mostrar_menu(chat_id, "Vale, no he guardado el gasto. 😊")
        return
    if data == "CG_OK":
        _guardar_gasto_confirmado(chat_id)
        return
    if data.startswith("GT|"):
        clave = data.split("|", 1)[1]
        if clave in TIPOS_GASTO:
            recibir_tipo_gasto(chat_id, clave)
        return
    if data.startswith("AVH|") or data.startswith("AVS|"):
        prefijo, key = data.split("|", 1)
        campo = _buscar_campo_avanzado(prefijo, key)
        if not campo:
            return
        _, label, tipo, auto_fn = campo
        if tipo == "bool":
            nueva = datos.setdefault(chat_id, {}).setdefault("nuevaCarga", {})
            actual = nueva.get(key, auto_fn(chat_id) if auto_fn else False)
            nueva[key] = not actual
            if prefijo == "AVH":
                mostrar_menu_avanzado_home(call.message)
            else:
                mostrar_menu_avanzado_street(call.message)
        else:
            _pedir_valor_campo_avanzado(call.message, prefijo, key)
        return
    if data == "AVH_OK" or data == "AVH_BACK":
        if data == "AVH_BACK":
            mostrar_menu_avanzado_home(call.message)
        else:
            mostrar_confirmacion_carga_casa(call.message)
        return
    if data == "AVS_OK" or data == "AVS_BACK":
        if data == "AVS_BACK":
            mostrar_menu_avanzado_street(call.message)
        else:
            mostrar_confirmacion_carga(call.message)
        return
    if data == "imp_no":
        datos.pop(chat_id, None)
        mostrar_menu(chat_id, "Vale, no he importado nada. 😊")
        return
    if data == "imp_ok":
        pendiente = datos.get(chat_id, {}).get("_import_pendiente")
        datos.pop(chat_id, None)
        if pendiente is None:
            bot.send_message(chat_id, "⚠️ No hay ninguna importación pendiente.")
            return
        try:
            _escribir_archivo_crudo(pendiente)
            mostrar_menu(chat_id, "✅ Backup importado correctamente.")
        except Exception:
            logger.exception("Error importando backup")
            bot.send_message(chat_id, "⚠️ No se pudo importar el backup.")
        return

    # Si la sesión se purgó pero la contraseña sigue recordada, se recupera sola en vez de
    # obligar al usuario a volver al menú y empezar de cero.
    password = datos.get(chat_id, {}).get("password") or _password_recordada(chat_id)
    if not password:
        bot.send_message(chat_id, "⚠️ Tu sesión ha caducado. Vuelve a pulsar '🗂️ Editar / Borrar registros' o '⚙️ Más opciones'.")
        return

    try:
        app_data, _ = cargar_datos(password)
    except CryptoJSError:
        _olvidar_password(chat_id)
        bot.send_message(chat_id, "❌ La contraseña ya no es válida. Vuelve a intentarlo desde el menú.")
        datos.pop(chat_id, None)
        return
    except Exception:
        logger.exception("Error leyendo el backup en callback de gestión")
        bot.send_message(chat_id, "⚠️ No se pudo leer el archivo del dashboard.")
        return

    _limpiar_intentos(chat_id)

    if data == "gm_back":
        bot.send_message(chat_id, "🗂️ ¿Qué quieres gestionar?", reply_markup=teclado_gestion_root())
    elif data == "mo_back":
        bot.send_message(chat_id, "⚙️ ¿Qué quieres hacer?", reply_markup=teclado_mas_opciones(chat_id))
    elif data == "mo_olvidar":
        _olvidar_password(chat_id)
        datos.pop(chat_id, None)
        bot.send_message(chat_id, "🔒 Contraseña olvidada. Te la volveré a pedir en la próxima acción.")
        mostrar_menu(chat_id)
        return
    elif data == "mo_resumen":
        mostrar_resumen(chat_id, app_data)
    elif data == "mo_stats":
        mostrar_estadisticas_avanzadas(chat_id, app_data)
    elif data == "mo_config":
        mostrar_configuracion(chat_id, app_data)
    elif data == "mo_exportar":
        exportar_backup(chat_id)
    elif data == "mo_importar_info":
        bot.send_message(
            chat_id,
            "📥 Para importar, envíame el archivo .json de backup como documento (adjunto).\n\n"
            "Te pediré confirmación antes de reemplazar los datos actuales.",
        )
    elif data == "mo_preset_iberdrola":
        settings = app_data.setdefault("settings", {})
        settings["tarifaModo"] = "tramos"
        settings["tarifaP1"] = 0.22
        settings["tarifaP2"] = 0.13
        settings["tarifaP3"] = 0.03
        _sincronizar_tarifa(settings)
        try:
            guardar_datos(app_data, password)
            bot.send_message(
                chat_id,
                "✅ Tarifa por tramos aplicada: 0,22 €/kWh en punta, "
                "0,13 € en llano y 0,03 € en valle.",
            )
        except Exception:
            logger.exception("Error guardando preset de tarifa")
            bot.send_message(chat_id, "⚠️ No se pudo guardar la tarifa.")
    elif data == "mo_gasoil":
        settings = app_data.setdefault("settings", {})
        provincia_settings = settings.get("provincia")
        nombre_carburante = _nombre_carburante(settings)
        precio, es_nuevo, fuente_carburante = _obtener_precio_carburante(provincia_settings, _tipo_carburante(settings))
        if precio is None:
            aviso_provincia = f" en la provincia '{provincia_settings}'" if provincia_settings else ""
            bot.send_message(chat_id, f"⚠️ No he podido consultar el precio de {nombre_carburante}{aviso_provincia} ahora mismo. Inténtalo más tarde.")
        else:
            anterior = settings.get("icePrice")
            settings["icePrice"] = precio
            # Actualizar a mano vuelve a poner el precio en automático: si el usuario pide
            # expresamente el precio real, es que quiere el real, no el suyo congelado.
            settings["icePriceAuto"] = True
            try:
                guardar_datos(app_data, password)
                origen = "consultado ahora" if es_nuevo else "de la última consulta (caché de unas horas)"
                consejo = (
                    ""
                    if provincia_settings else
                    "\n\n💡 Consejo: configura tu provincia en ⚙️ Configuración para usar el precio de tu zona en vez de la media nacional."
                )
                bot.send_message(
                    chat_id,
                    f"⛽ Precio de {nombre_carburante} actualizado a {precio}€/L ({fuente_carburante}, {origen}).\n\n"
                    f"Valor anterior: {anterior}€/L." + consejo,
                )
            except Exception:
                logger.exception("Error guardando el precio del carburante")
                bot.send_message(chat_id, "⚠️ No se pudo guardar el nuevo precio.")
    elif data.startswith("cfg|"):
        _iniciar_edicion_config(chat_id, data.split("|", 1)[1], password)
    elif data.startswith("cfgset|"):
        _, clave, valor = data.split("|", 2)
        if clave not in CONFIG_OPCIONES or valor not in CONFIG_OPCIONES[clave]:
            bot.send_message(chat_id, "⚠️ Opción no reconocida.")
            return
        settings = app_data.setdefault("settings", {})
        settings[clave] = valor
        if clave == "iceFuel":
            # Cambiar de combustible deja obsoleto el precio guardado del anterior, así que se
            # vuelve al automático para que se recalcule con el nuevo.
            settings["icePriceAuto"] = True
        _sincronizar_tarifa(settings, clave)
        try:
            guardar_datos(app_data, password)
            bot.send_message(chat_id, f"✅ {CONFIG_CAMPOS[clave][0]}: {CONFIG_OPCIONES[clave][valor]}")
            mostrar_configuracion(chat_id, app_data)
        except Exception:
            logger.exception("Error guardando opción de configuración")
            bot.send_message(chat_id, "⚠️ No se pudo guardar el cambio.")
    elif data == "mo_modelos":
        bot.send_message(
            chat_id,
            "🚘 *Modelos con datos ya rellenados*\n\n"
            "Sobrescribiré capacidad, autonomía y datos del coche de referencia.\n"
            "El resto (tarifas, cargador, precios de compra) no se toca.",
            parse_mode="Markdown",
            reply_markup=teclado_modelos(),
        )
    elif data.startswith("mdl|"):
        ficha = MODELOS_CONOCIDOS.get(data.split("|", 1)[1])
        if not ficha:
            bot.send_message(chat_id, "⚠️ Modelo no reconocido.")
            return
        settings = app_data.setdefault("settings", {})
        settings.update(ficha["settings"])
        settings["icePriceAuto"] = True
        try:
            guardar_datos(app_data, password)
        except Exception:
            logger.exception("Error aplicando ficha de modelo")
            bot.send_message(chat_id, "⚠️ No se pudieron guardar los datos del modelo.")
            return
        resumen = "\n".join(
            f"• {CONFIG_CAMPOS[k][0]}: {CONFIG_OPCIONES[k][v] if k in CONFIG_OPCIONES else v}{CONFIG_CAMPOS[k][2]}"
            for k, v in ficha["settings"].items() if k in CONFIG_CAMPOS
        )
        bot.send_message(
            chat_id,
            f"✅ *{ficha['nombre']}* aplicado.\n\n{resumen}\n\n{ficha['nota']}",
            parse_mode="Markdown",
        )
        mostrar_configuracion(chat_id, app_data)
    elif data == "gm_logs":
        _listar_logs_inline(chat_id, app_data)
    elif data == "gm_obd":
        _listar_obd_inline(chat_id, app_data)
    elif data == "gm_gastos":
        _listar_gastos_inline(chat_id, app_data)
    elif data.startswith("FIN|"):
        log = _buscar_por_id(app_data.get("logs", []), data.split("|", 1)[1])
        if not log:
            bot.send_message(chat_id, "⚠️ Esa carga ya no existe.")
            return
        _set_password_sesion(chat_id, password)
        _preguntar_percent_final_pendiente(chat_id, log)
    elif data.startswith("X|"):
        _confirmar_borrado_gasto(chat_id, data.split("|", 1)[1])
    elif data.startswith("XDY|"):
        gasto_id = data.split("|", 1)[1]
        app_data["gastos"] = [g for g in app_data.get("gastos", []) if str(g.get("id")) != str(gasto_id)]
        marcar_borrado(app_data, "gastos", gasto_id)
        try:
            guardar_datos(app_data, password)
            bot.send_message(chat_id, "🗑️ Gasto borrado correctamente.")
        except Exception:
            logger.exception("Error borrando gasto")
            bot.send_message(chat_id, "⚠️ No se pudo borrar el gasto.")
    elif data.startswith("L|"):
        _opciones_log(chat_id, data.split("|", 1)[1])
    elif data.startswith("O|"):
        _opciones_obd(chat_id, data.split("|", 1)[1])
    elif data.startswith("LD|"):
        _confirmar_borrado_log(chat_id, data.split("|", 1)[1])
    elif data.startswith("OD|"):
        _confirmar_borrado_obd(chat_id, data.split("|", 1)[1])
    elif data.startswith("LDY|"):
        log_id = data.split("|", 1)[1]
        app_data["logs"] = [l for l in app_data.get("logs", []) if str(l.get("id")) != str(log_id)]
        marcar_borrado(app_data, "logs", log_id)
        try:
            guardar_datos(app_data, password)
            bot.send_message(chat_id, "🗑️ Carga borrada correctamente.")
        except Exception:
            logger.exception("Error borrando carga")
            bot.send_message(chat_id, "⚠️ No se pudo borrar la carga.")
    elif data.startswith("ODY|"):
        obd_id = data.split("|", 1)[1]
        app_data["obd"] = [o for o in app_data.get("obd", []) if str(o.get("id")) != str(obd_id)]
        marcar_borrado(app_data, "obd", obd_id)
        try:
            guardar_datos(app_data, password)
            bot.send_message(chat_id, "🗑️ Registro de batería borrado correctamente.")
        except Exception:
            logger.exception("Error borrando registro OBD")
            bot.send_message(chat_id, "⚠️ No se pudo borrar el registro.")
    elif data.startswith("LE|"):
        log_id = data.split("|", 1)[1]
        log = _buscar_por_id(app_data.get("logs", []), log_id)
        if not log:
            bot.send_message(chat_id, "⚠️ No se encontró la carga.")
            return
        datos.setdefault(chat_id, {})["editLog"] = {"id": log_id, "overrides": {}}
        _set_password_sesion(chat_id, password)
        mostrar_menu_editar_log(chat_id)
    elif data.startswith("LF|"):
        _pedir_valor_campo_editar_log(chat_id, data.split("|", 1)[1])
    elif data == "LFOK":
        _guardar_edicion_log(chat_id)
    elif data == "LFCANCEL":
        datos.pop(chat_id, None)
        mostrar_menu(chat_id, "Vale, no he cambiado nada. 😊")
    elif data.startswith("OE|"):
        obd_id = data.split("|", 1)[1]
        obd = _buscar_por_id(app_data.get("obd", []), obd_id)
        if not obd:
            bot.send_message(chat_id, "⚠️ No se encontró el registro.")
            return
        datos.setdefault(chat_id, {})["editObd"] = {"id": obd_id}
        _set_password_sesion(chat_id, password)
        msg = bot.send_message(chat_id, f"✏️ Editando registro del {obd.get('date')}.\n\n🔋 Nuevo SoH % (actual: {obd.get('soh', 0)}):", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, editar_obd_soh)


CAMPOS_EDITAR_LOG = [
    ("date", "🕐 Fecha/hora inicio", "date"),
    ("dateEnd", "🏁 Fecha/hora fin", "date"),
    ("socStart", "🔋 % batería inicio", "num"),
    ("socEnd", "🔋 % batería final", "num"),
    ("kwh", "⚡ kWh cargados", "num"),
    ("cost", "💶 Coste total (€)", "num"),
    ("km", "🚗 Km parciales", "num"),
    ("odo", "🛣️ Odómetro (km)", "num"),
    ("power", "🔌 Potencia cargador (kW)", "num"),
    ("duration", "⏱️ Duración (min)", "num"),
    ("precond", "❄️ Precondicionamiento", "bool"),
    ("temp", "🌡️ Temp. exterior (°C)", "num"),
    ("subCost", "💶 Coste fijo/suscripción (€)", "num"),
    ("brand", "🏷️ Marca/operador", "text"),
]


def _buscar_campo_editar_log(key):
    return next((c for c in CAMPOS_EDITAR_LOG if c[0] == key), None)


def _valor_actual_editar_log(chat_id, log, key):
    overrides = datos.get(chat_id, {}).get("editLog", {}).get("overrides", {})
    if key in overrides:
        return overrides[key]
    return log.get(key)


def _duracion_calculada_editar_log(chat_id, log):
    """Minutos entre el inicio y el fin que se están editando ahora mismo (contando los cambios
    aún sin guardar), o None si falta alguna de las dos fechas."""
    return _minutos_entre(
        _valor_actual_editar_log(chat_id, log, "date"),
        _valor_actual_editar_log(chat_id, log, "dateEnd"),
    )


def _valor_mostrado_editar_log(chat_id, log, key, tipo):
    valor = _valor_actual_editar_log(chat_id, log, key)
    if valor is None or valor == "":
        if key == "duration":
            minutos = _duracion_calculada_editar_log(chat_id, log)
            if minutos is not None:
                return f"{minutos} min (auto)"
        return "sin definir"
    if tipo == "bool":
        return "Sí" if valor else "No"
    if tipo == "date":
        return _formatear_fecha_hora(valor)
    return str(valor)


def _teclado_editar_log(chat_id, log):
    t = InlineKeyboardMarkup()
    for key, label, tipo in CAMPOS_EDITAR_LOG:
        valor = _valor_mostrado_editar_log(chat_id, log, key, tipo)
        t.add(InlineKeyboardButton(f"{label}: {valor}", callback_data=f"LF|{key}"))
    t.add(
        InlineKeyboardButton("💾 Guardar cambios", callback_data="LFOK"),
        _boton_inline("❌ Cancelar", "LFCANCEL", ESTILO_PELIGRO),
    )
    return t


def mostrar_menu_editar_log(chat_id):
    estado = datos.get(chat_id, {})
    password = estado.get("password")
    log_id = estado.get("editLog", {}).get("id")
    try:
        app_data, _ = cargar_datos(password)
    except Exception:
        logger.exception("Error leyendo el backup al editar carga")
        mostrar_menu(chat_id, "⚠️ No se pudo leer el archivo.")
        datos.pop(chat_id, None)
        return
    log = _buscar_por_id(app_data.get("logs", []), log_id)
    if not log:
        mostrar_menu(chat_id, "⚠️ La carga ya no existe.")
        datos.pop(chat_id, None)
        return
    lugar_txt = "🏠 en casa" if log.get("type") == "home" else f"🛣️ en la calle ({_escapar_markdown(log.get('brand', 'Otros'))})"
    bot.send_message(
        chat_id,
        f"✏️ *Editando carga {lugar_txt}*\n\nPulsa un campo para cambiarlo. Cuando termines, pulsa 💾 Guardar cambios.",
        reply_markup=_teclado_editar_log(chat_id, log),
        parse_mode="Markdown",
    )


def _pedir_valor_campo_editar_log(chat_id, key):
    campo = _buscar_campo_editar_log(key)
    if not campo:
        return
    _, label, tipo = campo
    estado = datos.get(chat_id, {})
    password = estado.get("password")
    log_id = estado.get("editLog", {}).get("id")
    try:
        app_data, _ = cargar_datos(password)
        log = _buscar_por_id(app_data.get("logs", []), log_id) or {}
    except Exception:
        log = {}
    if tipo == "date":
        valor_actual = _valor_actual_editar_log(chat_id, log, key)
        iniciar_selector_fecha_hora(chat_id, f"EDITLOG_{key}", valor_actual)
        return
    if tipo == "bool":
        actual = _valor_actual_editar_log(chat_id, log, key)
        datos[chat_id].setdefault("editLog", {}).setdefault("overrides", {})[key] = not actual
        mostrar_menu_editar_log(chat_id)
        return
    datos[chat_id]["_editarLogCampoActual"] = key
    instrucciones = "Escribe solo el número." if tipo == "num" else "Escribe el nuevo texto."
    if key == "duration":
        minutos = _duracion_calculada_editar_log(chat_id, log)
        if minutos is not None:
            instrucciones += f"\n\n🤖 Por las horas anotadas son {minutos} min.\nEscribe un guion (-) para usar ese valor."
    msg = bot.send_message(chat_id, f"✏️ {label}\n\n{instrucciones}", reply_markup=teclado_cancelar())
    bot.register_next_step_handler(msg, recibir_valor_editar_log)


def recibir_valor_editar_log(message):
    if es_cancelacion(message):
        return
    chat_id = message.chat.id
    estado = datos.get(chat_id, {})
    key = estado.get("_editarLogCampoActual")
    campo = _buscar_campo_editar_log(key) if key else None
    if not campo:
        mostrar_menu(chat_id, "⚠️ La edición ha caducado.")
        datos.pop(chat_id, None)
        return
    _, label, tipo = campo
    if tipo == "num":
        valor_txt = message.text.replace(',', '.').strip()
        if key == "duration" and valor_txt == "-":
            try:
                app_data, _ = cargar_datos(estado.get("password"))
                log = _buscar_por_id(app_data.get("logs", []), estado.get("editLog", {}).get("id")) or {}
            except Exception:
                log = {}
            minutos = _duracion_calculada_editar_log(chat_id, log)
            if minutos is None:
                msg = bot.send_message(chat_id, "🙈 Aún no tengo las dos horas.\nEscribe los minutos a mano.", reply_markup=teclado_cancelar())
                bot.register_next_step_handler(msg, recibir_valor_editar_log)
                return
            valor_txt = str(minutos)
        if not _es_numero(valor_txt):
            msg = bot.send_message(chat_id, "🙈 Escribe solo un número.", reply_markup=teclado_cancelar())
            bot.register_next_step_handler(msg, recibir_valor_editar_log)
            return
        valor_final = float(valor_txt)
    else:
        valor_final = message.text.strip().replace("\n", " ")[:60]
        if not valor_final:
            msg = bot.send_message(chat_id, "🙈 Escribe un texto, no puede estar vacío.", reply_markup=teclado_cancelar())
            bot.register_next_step_handler(msg, recibir_valor_editar_log)
            return
    estado.setdefault("editLog", {}).setdefault("overrides", {})[key] = valor_final
    mostrar_menu_editar_log(chat_id)


def _guardar_edicion_log(chat_id):
    estado = datos.get(chat_id, {})
    password = estado.get("password")
    edit = estado.get("editLog", {})
    overrides = edit.get("overrides", {})

    try:
        app_data, _ = cargar_datos(password)
    except Exception:
        logger.exception("Error leyendo el backup al editar carga")
        mostrar_menu(chat_id, "⚠️ No se pudo guardar el cambio.")
        datos.pop(chat_id, None)
        return

    log = _buscar_por_id(app_data.get("logs", []), edit.get("id"))
    if not log:
        mostrar_menu(chat_id, "⚠️ La carga ya no existe.")
        datos.pop(chat_id, None)
        return

    for key, valor in overrides.items():
        log[key] = valor

    # La duración sale sola de las dos fechas: no tiene sentido dejarla vacía si hay inicio y
    # fin, ni conservar la vieja si se acaba de corregir alguna de las dos horas.
    if "duration" not in overrides:
        minutos = _minutos_entre(log.get("date"), log.get("dateEnd"))
        if minutos is not None and (not log.get("duration") or "date" in overrides or "dateEnd" in overrides):
            log["duration"] = minutos

    # Si al editar se ha puesto el % final, la carga deja de estar pendiente: si no,
    # seguiría saliendo en la lista de "Cerrar carga" aunque ya esté completa.
    if log.get("pendingFinal") and log.get("socEnd") is not None:
        log["pendingFinal"] = False

    try:
        guardar_datos(app_data, password)
    except Exception:
        logger.exception("Error guardando edición de carga")
        mostrar_menu(chat_id, "⚠️ No se pudo guardar el cambio en el archivo.")
        datos.pop(chat_id, None)
        return

    datos.pop(chat_id, None)
    if overrides:
        mostrar_menu(chat_id, f"✅ Carga actualizada ({len(overrides)} campo(s) modificado(s)).")
    else:
        mostrar_menu(chat_id, "ℹ️ No has cambiado ningún campo.")


def editar_obd_soh(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not valor.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, editar_obd_soh)
        return
    datos.setdefault(message.chat.id, {}).setdefault("editObd", {})["soh"] = float(valor)
    msg = bot.send_message(message.chat.id, "🚗 Nuevo odómetro (km):", reply_markup=teclado_cancelar())
    bot.register_next_step_handler(msg, editar_obd_odo)


def editar_obd_odo(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not valor.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, editar_obd_odo)
        return
    datos.setdefault(message.chat.id, {}).setdefault("editObd", {})["odo"] = float(valor)
    msg = bot.send_message(message.chat.id, "🔢 Nueva capacidad (kWh):", reply_markup=teclado_cancelar())
    bot.register_next_step_handler(msg, editar_obd_cap)


def editar_obd_cap(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not valor.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, editar_obd_cap)
        return
    datos.setdefault(message.chat.id, {}).setdefault("editObd", {})["cap"] = float(valor)
    msg = bot.send_message(message.chat.id, "⚖️ Nuevo desbalanceo (mV):", reply_markup=teclado_cancelar())
    bot.register_next_step_handler(msg, editar_obd_mv)


def editar_obd_mv(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not valor.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, editar_obd_mv)
        return
    datos.setdefault(message.chat.id, {}).setdefault("editObd", {})["mv"] = float(valor)
    msg = bot.send_message(message.chat.id, "🔁 Nuevos ciclos de carga:", reply_markup=teclado_cancelar())
    bot.register_next_step_handler(msg, editar_obd_cycles)


def editar_obd_cycles(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not valor.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, editar_obd_cycles)
        return
    datos.setdefault(message.chat.id, {}).setdefault("editObd", {})["cycles"] = float(valor)
    guardar_edicion_obd(message)


def guardar_edicion_obd(message):
    chat_id = message.chat.id
    estado = datos.get(chat_id, {})
    password = estado.get("password")
    edit = estado.get("editObd", {})

    try:
        app_data, _ = cargar_datos(password)
    except Exception:
        logger.exception("Error leyendo el backup al editar OBD")
        mostrar_menu(chat_id, "⚠️ No se pudo guardar el cambio.")
        datos.pop(chat_id, None)
        return

    obd = _buscar_por_id(app_data.get("obd", []), edit.get("id"))
    if not obd:
        mostrar_menu(chat_id, "⚠️ El registro ya no existe.")
        datos.pop(chat_id, None)
        return

    obd["soh"] = edit.get("soh", obd.get("soh"))
    obd["odo"] = edit.get("odo", obd.get("odo"))
    obd["cap"] = edit.get("cap", obd.get("cap"))
    obd["mv"] = edit.get("mv", obd.get("mv"))
    obd["cycles"] = edit.get("cycles", obd.get("cycles"))

    try:
        guardar_datos(app_data, password)
    except Exception:
        logger.exception("Error guardando edición de OBD")
        mostrar_menu(chat_id, "⚠️ No se pudo guardar el cambio en el archivo.")
        datos.pop(chat_id, None)
        return

    datos.pop(chat_id, None)
    mostrar_menu(chat_id, f"✅ Registro actualizado: SoH {obd['soh']}%, {obd['odo']} km, {obd['cap']} kWh.")


@bot.message_handler(func=lambda m: True, content_types=['text'])
def mensaje_no_reconocido(message):
    mostrar_menu(message.chat.id, "🤔 No he entendido ese mensaje. Elige una opción pulsando un botón 👇")


if __name__ == '__main__':
    logger.info('Iniciando EVBot')
    # Muy importante: si ev_manager.html no ve las cargas nuevas que sí ves en el bot,
    # lo primero a comprobar es que esta ruta sea EXACTAMENTE el mismo archivo que usa
    # el servidor web para servir ev_backup.json junto a ev_manager.html (mismo path,
    # no solo "el mismo NAS": si el bot corre en un contenedor/LXD, esta ruta vive dentro
    # de su propio filesystem salvo que sea un bind-mount al recurso compartido real).
    logger.info('Archivo de backup: %s (existe: %s)', EV_BACKUP_PATH, os.path.exists(EV_BACKUP_PATH))
    _iniciar_purgador_sesiones()
    _iniciar_avisos()
    _registrar_comandos()

    # `infinity_polling(skip_pending=True)` hace la primera llamada a Telegram (para descartar
    # mensajes viejos) FUERA de su bucle interno de reintentos, así que si en ese instante no hay
    # red / DNS / certificado válido, el proceso moría con traceback y código de salida 1 en vez de
    # esperar y reintentar. Este bucle envuelve el arranque para que un corte de red temporal (o un
    # arranque del sistema antes de que la red esté lista) no tumbe el bot.
    while True:
        try:
            bot.infinity_polling(skip_pending=True, timeout=20, long_polling_timeout=20)
            break  # salida limpia (bot.stop_polling())
        except KeyboardInterrupt:
            logger.info('Detenido manualmente (Ctrl+C)')
            break
        except requests.exceptions.RequestException as exc:
            # Fallo de red/TLS: casi siempre temporal (sin conexión, DNS, proxy, o reloj del
            # sistema mal puesto -> "certificado fuera de su periodo de validez").
            logger.error('Sin conexión con Telegram: %s', _ocultar_token(exc))
            logger.info('Reintento en %s segundos...', REINTENTO_CONEXION_SEGUNDOS)
            time.sleep(REINTENTO_CONEXION_SEGUNDOS)
        except Exception as exc:
            # Error no relacionado con la red (p.ej. token inválido): reintentar no sirve de nada.
            logger.error('Error irrecuperable al arrancar el polling: %s', _ocultar_token(exc))
            break
    logger.info('Fin de la ejecución')
