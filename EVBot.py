# -*- coding: utf-8 -*-

from config import *
#pip install pyTelegramBotAPI
#pip install pycryptodome
import base64
import copy
import hashlib
import json
import logging
import os
import shutil
import time
import requests
import telebot
from telebot.types import ReplyKeyboardMarkup, InlineKeyboardMarkup, InlineKeyboardButton
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


# Misma estructura por defecto que "defaultData" en ev_manager.html
DEFAULT_APP_DATA = {
    "settings": {
        "model": "Opel Mokka-e", "capacity": 46, "wltp": 332, "efficiency": 80,
        "priceEV": 32000, "priceICE": 22000, "iceLiters": 5.8, "icePrice": 1.50,
        "pDay": 0.22, "pNight": 0.03, "homePower": 4.4,
    },
    "logs": [],
    "obd": [],
}


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
        return json.loads(texto), False
    return crudo, False


def guardar_datos(app_data, password=None):
    """Escribe el backup de forma atómica, cifrado con AES (compatible con CryptoJS) si hay contraseña."""
    texto = json.dumps(app_data, ensure_ascii=False)
    if password:
        contenido = {"isEncrypted": True, "content": encrypt_cryptojs(texto, password)}
    else:
        contenido = app_data
    _escribir_archivo_crudo(contenido)


# --- Valores por defecto para la rutina real de carga nocturna en casa (00:05h-07:00h) ---
HORA_INICIO_CARGA_DEFECTO = "00:05"
HORA_FIN_CARGA_DEFECTO = "07:00"


def _parsear_hora_hhmm(texto):
    """Convierte 'HH:MM' en (hora, minuto) o devuelve None si el formato/valores no son válidos."""
    partes = texto.strip().split(":")
    if len(partes) != 2 or not partes[0].isdigit() or not partes[1].isdigit():
        return None
    hora, minuto = int(partes[0]), int(partes[1])
    if not (0 <= hora <= 23 and 0 <= minuto <= 59):
        return None
    return hora, minuto


def _calcular_duracion_min(hora_inicio_str, hora_fin_str):
    """Minutos entre hora_inicio_str y hora_fin_str (HH:MM), asumiendo que fin puede caer al día siguiente."""
    ini = _parsear_hora_hhmm(hora_inicio_str)
    fin = _parsear_hora_hhmm(hora_fin_str)
    if not ini or not fin:
        return 0
    inicio_dt = datetime.datetime(2000, 1, 1, ini[0], ini[1])
    fin_dt = datetime.datetime(2000, 1, 1, fin[0], fin[1])
    if fin_dt <= inicio_dt:
        fin_dt += datetime.timedelta(days=1)
    return int((fin_dt - inicio_dt).total_seconds() // 60)


DURACION_CARGA_DEFECTO_MIN = _calcular_duracion_min(HORA_INICIO_CARGA_DEFECTO, HORA_FIN_CARGA_DEFECTO)


def _capacidad_efectiva(app_data):
    """Capacidad útil de la batería (kWh), ajustada por el último SoH conocido si hay lecturas OBD."""
    settings = app_data.get("settings", {})
    capacidad = settings.get("capacity", 46) or 46
    obd = app_data.get("obd", [])
    if obd:
        ultimo = sorted(obd, key=lambda o: o.get("date", ""))[-1]
        soh = ultimo.get("soh")
        if soh:
            return capacidad * (soh / 100)
    return capacidad


def _tarifa_para_hora(app_data, hora_str):
    """Devuelve el precio €/kWh según el horario (igual que updateHomeRate() en el dashboard: 01:00h-07:00h es valle)."""
    settings = app_data.get("settings", {})
    try:
        hora = int(hora_str.split(":")[0])
    except (ValueError, IndexError, AttributeError):
        hora = 0
    if 1 <= hora < 7:
        return settings.get("pNight", 0.03) or 0.03
    return settings.get("pDay", 0.22) or 0.22


_precio_gasoil_cache = {"valor": None, "ts": None, "fuente": None}
PRECIO_GASOIL_CACHE_HORAS = 6


def _obtener_precio_gasoil_actual():
    """Consulta el precio medio actual del Gasóleo A en España (API abierta oficial del Gobierno,
    Ministerio para la Transición Ecológica) para no depender de que el usuario lo busque a mano.
    Devuelve (precio, es_nuevo) o (None, False) si nunca se pudo obtener. Cachea unas horas para no
    descargar el listado completo de gasolineras en cada consulta."""
    ahora = datetime.datetime.now()
    cache = _precio_gasoil_cache
    if cache["valor"] is not None and cache["ts"] and (ahora - cache["ts"]).total_seconds() < PRECIO_GASOIL_CACHE_HORAS * 3600:
        return cache["valor"], False
    try:
        resp = requests.get(
            "https://sedeaplicaciones.minetur.gob.es/ServiciosRESTCarburantes/PreciosCarburantes/EstacionesTerrestres/",
            timeout=25,
            headers={"User-Agent": "EVBot/1.0"},
        )
        resp.raise_for_status()
        datos_api = resp.json()
        precios = []
        for estacion in datos_api.get("ListaEESSPrecio", []):
            valor_txt = (estacion.get("Precio Gasoleo A") or "").strip()
            if not valor_txt:
                continue
            try:
                precios.append(float(valor_txt.replace(",", ".")))
            except ValueError:
                continue
        if not precios:
            return cache["valor"], False
        media = round(sum(precios) / len(precios), 3)
        cache["valor"] = media
        cache["ts"] = ahora
        cache["fuente"] = f"media de {len(precios)} gasolineras en España"
        return media, True
    except Exception:
        logger.exception("No se pudo obtener el precio del gasóleo A actual (se usará el último conocido o el configurado)")
        return cache["valor"], False


# --- Botones del menú: todo se maneja pulsando botones, sin necesidad de escribir comandos ---
BTN_RECARGA = "💰 Precio de la recarga"
BTN_TIEMPO = "⏰ ¿Cuándo desenchufar?"
BTN_RAPIDA22 = "⚡ Carga rápida 22kWh"
BTN_RAPIDA55 = "⚡ Carga rápida 55kWh"
BTN_EQUIVALENCIAS = "🔋 Equivalencias"
BTN_AYUDA = "❓ Ayuda"
BTN_CANCELAR = "❌ Cancelar"
BTN_CASA = "🏠 En Casa"
BTN_CALLE = "🛣️ En la calle"
BTN_ANOTAR = "📒 Anotar carga (Dashboard)"
BTN_VER_CARGAS = "📊 Ver últimas cargas"
BTN_OBD_ANOTAR = "🔧 Registrar batería (OBD)"
BTN_VER_OBD = "🔎 Ver batería (OBD)"
BTN_GESTIONAR = "🗂️ Editar / Borrar registros"
BTN_MAS = "⚙️ Más opciones"
BTN_FINALIZAR_CARGA = "🌙➡️☀️ Añadir % final de anoche"


def teclado_menu():
    """Menú principal con botones grandes, siempre visible."""
    teclado = ReplyKeyboardMarkup(resize_keyboard=True)
    teclado.add(BTN_RECARGA, BTN_TIEMPO)
    teclado.add(BTN_RAPIDA22, BTN_RAPIDA55)
    teclado.add(BTN_ANOTAR, BTN_FINALIZAR_CARGA)
    teclado.add(BTN_OBD_ANOTAR, BTN_VER_CARGAS)
    teclado.add(BTN_VER_OBD, BTN_GESTIONAR)
    teclado.add(BTN_MAS)
    teclado.add(BTN_EQUIVALENCIAS, BTN_AYUDA)
    return teclado


def teclado_cancelar():
    """Teclado simple para poder cancelar en cualquier momento."""
    teclado = ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True)
    teclado.add(BTN_CANCELAR)
    return teclado


def teclado_lugar():
    teclado = ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True)
    teclado.add(BTN_CASA, BTN_CALLE)
    teclado.add(BTN_CANCELAR)
    return teclado


def mostrar_menu(chat_id, texto="👇 ¿Qué quieres hacer ahora? Elige una opción:"):
    bot.send_message(chat_id, texto, reply_markup=teclado_menu())


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


@bot.message_handler(func=lambda m: not usuario_autorizado(m.chat.id))
def acceso_denegado(message):
    """Bloquea a cualquier usuario que no esté en ALLOWED_USER_IDS. Al estar registrado
    el primero, intercepta el mensaje antes que cualquier otro manejador."""
    logger.warning("Acceso bloqueado para chat_id=%s (usuario no autorizado)", message.chat.id)
    bot.send_message(message.chat.id, "🚫 No tienes permiso para usar este bot. Contacta con el administrador si crees que es un error.")


@bot.message_handler(commands=["start", "ayuda"])
def start(message):
    texto = ("👋 ¡Hola! Soy *EVBot*.\n\n"
        "Te ayudo con la carga de tu coche eléctrico. No necesitas escribir nada raro, "
        "solo pulsa uno de los botones de abajo 👇\n\n"
        "💰 *Precio de la recarga*: cuánto te va a costar cargar el coche.\n"
        "⏰ *¿Cuándo desenchufar?*: a qué hora terminará la carga.\n"
        "⚡ *Carga rápida 22kWh / 55kWh*: tiempo aproximado en cargadores rápidos.\n"
        f"📒 *Anotar carga (Dashboard)*: para casa solo te pido % inicial, km parciales y odómetro "
        f"(carga nocturna {HORA_INICIO_CARGA_DEFECTO}h-{HORA_FIN_CARGA_DEFECTO}h por defecto, editable). "
        "Para la calle te pido los datos de la carga.\n"
        "🌙➡️☀️ *Añadir % final de anoche*: al día siguiente, con el % final calculo solo los kWh y el coste.\n"
        "🔧 *Registrar batería (OBD)*: guarda una lectura de salud de batería (SoH, km, etc.).\n"
        "📊 *Ver últimas cargas* / 🔎 *Ver batería (OBD)*: consulta lo último guardado.\n"
        "🗂️ *Editar / Borrar registros*: modifica o elimina cargas y lecturas ya guardadas.\n"
        "⚙️ *Más opciones*: resumen de ahorro, configuración, tarifas, precio del gasóleo "
        "actualizado en automático y copias de seguridad.\n"
        "🔋 *Equivalencias*: cuántos km da cada % de batería.")
    bot.send_message(message.chat.id, texto, reply_markup=teclado_menu(), parse_mode="Markdown")


@bot.message_handler(func=lambda m: m.text == BTN_AYUDA)
def ayuda_boton(message):
    start(message)


@bot.message_handler(commands=["equivalencias"])
@bot.message_handler(func=lambda m: m.text == BTN_EQUIVALENCIAS)
def equivalencias(message):
    bot.send_message(message.chat.id, """🔋 EQUIVALENCIAS DE BATERÍA (situación normal)

- 2% ➜ 5 km ➜ 1 kWh
- 10% ➜ 25 km ➜ 5 kWh
- 20% ➜ 50 km ➜ 10 kWh
- 25% ➜ 62,50 km ➜ 12,50 kWh
- 32% ➜ 80 km ➜ 16 kWh
- 40% ➜ 100 km ➜ 20 kWh
- 50% ➜ 125 km ➜ 25 kWh
- 60% ➜ 150 km ➜ 30 kWh
- 70% ➜ 175 km ➜ 35 kWh
- 80% ➜ 200 km ➜ 40 kWh
- 85% ➜ 212,50 km ➜ 42,50 kWh
- 100% ➜ 250 km ➜ 50 kWh""", reply_markup=teclado_menu())

@bot.message_handler(commands=["recarga"])
@bot.message_handler(func=lambda m: m.text == BTN_RECARGA)
def recarga(message):
    msg = bot.send_message(message.chat.id, "🔋 ¿Qué porcentaje de batería vas a cargar?\n\nEscribe solo el número, por ejemplo: 50", reply_markup=teclado_cancelar())
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
            msg = bot.send_message(message.chat.id, "💶 ¿A cuánto está el kWh ahí? (en euros)\n\nEjemplo: 0.35", reply_markup=teclado_cancelar())
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
    msg = bot.send_message(message.chat.id, "⏰ ¿Cuántos minutos va a estar cargando?\n\nEscribe solo el número, por ejemplo: 90", reply_markup=teclado_cancelar())
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


@bot.message_handler(commands=["tiempoRealCarga22kWh"])
@bot.message_handler(func=lambda m: m.text == BTN_RAPIDA22)
def recargaTiempoReal(message):
    msg = bot.send_message(message.chat.id, "🔋 ¿Qué porcentaje de batería tiene ahora mismo?\n\nEscribe solo el número, por ejemplo: 20", reply_markup=teclado_cancelar())
    bot.register_next_step_handler(msg, calculoTiempoRecargaReal)

def calculoTiempoRecargaReal(message):
    if es_cancelacion(message):
        return
    porcentajeActual = message.text.strip()
    if not porcentajeActual.isdigit():
        msg = bot.send_message(message.chat.id, "🙈 No te he entendido. Escribe solo el número, por ejemplo: 20", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, calculoTiempoRecargaReal)
    else:
        porcentajeCarga = 100 - int(porcentajeActual)
        # Porcentaje cargado en 93 minutos
        porcentaje1 = 14
        # Calculamos los minutos necesarios para llegar al porcentaje deseado
        minutos2 = (porcentajeCarga * 93) / porcentaje1
        minutosRedondeados = round(minutos2)
        horaActual = datetime.datetime.now()
        horaFinalizacion = horaActual + datetime.timedelta(minutes=int(minutosRedondeados))
        horaFinalString = str(horaFinalizacion.hour).zfill(2)+":"+str(horaFinalizacion.minute).zfill(2)
        horas = minutosRedondeados // 60
        minutos_restantes = minutosRedondeados % 60
        resultado = "{:02d}:{:02d}".format(horas, minutos_restantes)

        msg = (f"🔌 Lo has enchufado a las {horaActual.hour:02d}:{horaActual.minute:02d}h.\n\n"
               f"✅ La carga terminará sobre las {horaFinalString}h.\n\n"
               f"🔋 Se cargará un {porcentajeCarga}% hasta llegar al 100%, tardando aproximadamente {resultado} horas.")
        bot.send_message(message.chat.id, msg)
        mostrar_menu(message.chat.id)


@bot.message_handler(commands=["tiempoCarga55kWh"])
@bot.message_handler(func=lambda m: m.text == BTN_RAPIDA55)
def recargaTiempoRealRapida(message):
    msg = bot.send_message(message.chat.id, "🔋 ¿Qué porcentaje de batería tiene ahora mismo?\n\nEscribe solo el número, por ejemplo: 20", reply_markup=teclado_cancelar())
    bot.register_next_step_handler(msg, calculoTiempoRecargaRapida)

def calculoTiempoRecargaRapida(message):
    if es_cancelacion(message):
        return
    porcentajeActual = message.text.strip()
    if not porcentajeActual.isdigit():
        msg = bot.send_message(message.chat.id, "🙈 No te he entendido. Escribe solo el número, por ejemplo: 20", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, calculoTiempoRecargaRapida)
    else:
        porcentajeHasta85 = 85 - int(porcentajeActual)
        tiempoCargaHasta85 = porcentajeHasta85
        tiempoCargaDesde85 = 15 * 2
        tiempoTotal = tiempoCargaHasta85 + tiempoCargaDesde85

        horasTotal = tiempoTotal // 60
        minutosTotal = tiempoTotal % 60

        horaActual = datetime.datetime.now()
        horaFinalizacionHasta85 = horaActual + datetime.timedelta(minutes=tiempoCargaHasta85)
        horaFinalizacionDesde85 = horaFinalizacionHasta85 + datetime.timedelta(minutes=tiempoCargaDesde85)

        horaFinalHasta85String = str(horaFinalizacionHasta85.hour).zfill(2) + ":" + str(horaFinalizacionHasta85.minute).zfill(2)
        horaFinalDesde85String = str(horaFinalizacionDesde85.hour).zfill(2) + ":" + str(horaFinalizacionDesde85.minute).zfill(2)

        if horasTotal > 0:
            tiempoTotalString = f"{horasTotal:02d}:{minutosTotal:02d}"
        else:
            tiempoTotalString = f"{minutosTotal} minutos"

        msg = (f"🔌 Lo has enchufado a las {horaActual.hour:02d}:{horaActual.minute:02d}h.\n\n"
               f"✅ Hasta el 85% terminará a las {horaFinalHasta85String}h, y hasta el 100% a las {horaFinalDesde85String}h.\n\n"
               f"⏱️ Tiempo total de carga: {tiempoTotalString}.")
        bot.send_message(message.chat.id, msg)
        mostrar_menu(message.chat.id)



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


@bot.message_handler(commands=["anotarcarga"])
@bot.message_handler(func=lambda m: m.text == BTN_ANOTAR)
def anotar_carga_inicio(message):
    chat_id = message.chat.id
    if _password_bloqueada(chat_id):
        mostrar_menu(chat_id, f"🚫 Demasiados intentos fallidos. Espera {_minutos_restantes_bloqueo(chat_id)} min. antes de volver a intentarlo.")
        return
    datos[chat_id] = {"nuevaCarga": {}}
    if EV_BACKUP_PASSWORD:
        datos[chat_id]["password"] = EV_BACKUP_PASSWORD
        preguntar_lugar_carga(message)
    else:
        msg = bot.send_message(
            chat_id,
            "🔑 Para guardar la carga en el dashboard necesito la contraseña del archivo cifrado.\n\n"
            "Si es la primera vez, escribe la contraseña que quieras usar (la necesitarás también en el dashboard web).\n\n"
            "⚠️ Intentaré borrar tu mensaje después de leerlo por seguridad.",
            reply_markup=teclado_cancelar(),
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
    datos.setdefault(chat_id, {"nuevaCarga": {}})["password"] = password
    preguntar_lugar_carga(message)


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
        # Rutina real: por la noche solo se conocen % inicial, km parciales y odómetro.
        # El % final (y por tanto kWh/coste) se añaden al día siguiente ya cargados.
        nueva = datos[chat_id]["nuevaCarga"]
        nueva["type"] = "home"
        nueva["horaInicio"] = HORA_INICIO_CARGA_DEFECTO
        nueva["horaFin"] = HORA_FIN_CARGA_DEFECTO
        msg = bot.send_message(
            chat_id,
            f"🔋 ¿Con qué % de batería has enchufado el coche? (carga nocturna {HORA_INICIO_CARGA_DEFECTO}h-{HORA_FIN_CARGA_DEFECTO}h por defecto)\n\nEjemplo: 35",
            reply_markup=teclado_cancelar(),
        )
        bot.register_next_step_handler(msg, recibir_percent_inicial_casa)
        return
    datos[chat_id]["nuevaCarga"]["type"] = "street"
    msg = bot.send_message(chat_id, "🔋 ¿Cuántos kWh has cargado?\n\nEjemplo: 25.5", reply_markup=teclado_cancelar())
    bot.register_next_step_handler(msg, recibir_kwh_carga)


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
    mostrar_confirmacion_carga_casa(message)


def recibir_nueva_hora_inicio_casa(message):
    if es_cancelacion(message):
        return
    resultado = _parsear_hora_hhmm(message.text)
    if not resultado:
        msg = bot.send_message(message.chat.id, "🙈 Usa el formato HH:MM, por ejemplo 00:05", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_nueva_hora_inicio_casa)
        return
    hora, minuto = resultado
    nueva = datos.setdefault(message.chat.id, {}).setdefault("nuevaCarga", {})
    nueva["horaInicio"] = f"{hora:02d}:{minuto:02d}"
    msg = bot.send_message(
        message.chat.id,
        f"⏰ Ahora escribe la hora de fin de carga (formato HH:MM, actual: {nueva.get('horaFin', HORA_FIN_CARGA_DEFECTO)}):",
        reply_markup=teclado_cancelar(),
    )
    bot.register_next_step_handler(msg, recibir_nueva_hora_fin_casa)


def recibir_nueva_hora_fin_casa(message):
    if es_cancelacion(message):
        return
    resultado = _parsear_hora_hhmm(message.text)
    if not resultado:
        msg = bot.send_message(message.chat.id, "🙈 Usa el formato HH:MM, por ejemplo 07:00", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_nueva_hora_fin_casa)
        return
    hora, minuto = resultado
    nueva = datos.setdefault(message.chat.id, {}).setdefault("nuevaCarga", {})
    nueva["horaFin"] = f"{hora:02d}:{minuto:02d}"
    mostrar_confirmacion_carga_casa(message)


def mostrar_confirmacion_carga_casa(message):
    chat_id = message.chat.id
    nueva = datos.get(chat_id, {}).get("nuevaCarga", {})
    hora_inicio = nueva.get("horaInicio", HORA_INICIO_CARGA_DEFECTO)
    hora_fin = nueva.get("horaFin", HORA_FIN_CARGA_DEFECTO)
    resumen = (
        "📋 *Resumen de la carga (casa, nocturna):*\n\n"
        f"🔌 Horario: {hora_inicio}h → {hora_fin}h (editable)\n"
        f"🔋 % inicial: {nueva.get('socStart', 0)}%\n"
        f"🚗 Km parciales: {nueva.get('km', 0)} km\n"
        f"🛣️ Odómetro: {nueva.get('odo', 0)} km\n\n"
        "⏳ El % final, los kWh cargados y el coste se calcularán solos mañana con "
        "'🌙➡️☀️ Añadir % final de anoche'.\n\n"
        "¿Guardo esta carga en el dashboard?"
    )
    t = InlineKeyboardMarkup()
    t.add(InlineKeyboardButton("✅ Guardar", callback_data="CL_OK"))
    t.add(InlineKeyboardButton("✏️ Cambiar horario", callback_data="CL_HORA"))
    t.add(InlineKeyboardButton("❌ Cancelar", callback_data="CL_NO"))
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
    msg = bot.send_message(message.chat.id, "💶 ¿Cuánto te ha costado en total? (€)\n\nEjemplo: 8.50", reply_markup=teclado_cancelar())
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
    msg = bot.send_message(message.chat.id, "🚗 ¿Cuántos km has hecho desde la última carga?\n\nSi no lo sabes, escribe 0", reply_markup=teclado_cancelar())
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
    mostrar_confirmacion_carga(message)


def mostrar_confirmacion_carga(message):
    chat_id = message.chat.id
    nueva = datos.get(chat_id, {}).get("nuevaCarga", {})
    lugar_txt = "🏠 En casa" if nueva.get("type") == "home" else f"🛣️ En la calle ({nueva.get('brand', 'Otros')})"
    resumen = (f"📋 *Resumen de la carga:*\n\n"
               f"{lugar_txt}\n"
               f"🔋 {nueva.get('kwh', 0)} kWh\n"
               f"💶 {nueva.get('cost', 0)}€\n"
               f"🚗 {nueva.get('km', 0)} km\n\n"
               f"¿Guardo esta carga en el dashboard?")
    t = InlineKeyboardMarkup()
    t.add(
        InlineKeyboardButton("✅ Guardar", callback_data="CL_OK"),
        InlineKeyboardButton("❌ Cancelar", callback_data="CL_NO"),
    )
    bot.send_message(chat_id, resumen, reply_markup=t, parse_mode="Markdown")


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
        # Flujo simplificado de carga nocturna: solo se conocen % inicial, km parciales y odómetro.
        # kWh y coste quedan pendientes hasta que se añada el % final al día siguiente.
        settings = app_data.get("settings", {})
        fecha_hoy = datetime.datetime.now().strftime("%Y-%m-%d")
        hora_inicio = nueva.get("horaInicio", HORA_INICIO_CARGA_DEFECTO)
        hora_fin = nueva.get("horaFin", HORA_FIN_CARGA_DEFECTO)
        entrada = {
            "id": int(datetime.datetime.now().timestamp() * 1000),
            "date": f"{fecha_hoy}T{hora_inicio}",
            "km": nueva.get("km", 0),
            "kwh": 0,
            "cost": 0,
            "type": "home",
            "socStart": nueva.get("socStart", 0),
            "odo": nueva.get("odo", 0),
            "power": settings.get("homePower", 4.4),
            "duration": _calcular_duracion_min(hora_inicio, hora_fin),
            "pendingFinal": True,
        }
        app_data.setdefault("logs", []).append(entrada)
        try:
            guardar_datos(app_data, password)
        except Exception:
            logger.exception("Error escribiendo el backup")
            mostrar_menu(chat_id, "⚠️ No he podido guardar la carga en el archivo. Avisa al administrador.")
            datos.pop(chat_id, None)
            return
        resumen = (
            "✅ ¡Carga de esta noche guardada!\n\n"
            f"🔌 {hora_inicio}h → {nueva.get('horaFin', HORA_FIN_CARGA_DEFECTO)}h\n"
            f"🔋 % inicial: {entrada['socStart']}%\n"
            f"🚗 Km parciales: {entrada['km']} km · Odómetro: {entrada['odo']} km\n\n"
            "⏳ Mañana usa '🌙➡️☀️ Añadir % final de anoche' para completar kWh y coste automáticamente."
        )
        if es_nuevo:
            resumen += "\n\n📁 Se ha creado un archivo nuevo. Usa esta misma contraseña en el dashboard web para verlo."
        datos.pop(chat_id, None)
        mostrar_menu(chat_id, resumen)
        return

    # Flujo normal (carga pública / calle): todos los datos ya se conocen en el momento.
    entrada = {
        "id": int(datetime.datetime.now().timestamp() * 1000),
        "date": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M"),
        "km": nueva.get("km", 0),
        "kwh": nueva.get("kwh", 0),
        "cost": nueva.get("cost", 0),
        "type": nueva.get("type", "home"),
    }
    if nueva.get("type") == "street" and nueva.get("brand"):
        entrada["brand"] = nueva["brand"]

    app_data.setdefault("logs", []).append(entrada)

    try:
        guardar_datos(app_data, password)
    except Exception:
        logger.exception("Error escribiendo el backup")
        mostrar_menu(chat_id, "⚠️ No he podido guardar la carga en el archivo. Avisa al administrador.")
        datos.pop(chat_id, None)
        return

    lugar_txt = "🏠 en casa" if entrada["type"] == "home" else f"🛣️ en la calle ({entrada.get('brand', 'Otros')})"
    resumen = (f"✅ ¡Carga guardada en el dashboard!\n\n"
               f"{lugar_txt}\n"
               f"🔋 {entrada['kwh']} kWh\n"
               f"💶 {entrada['cost']}€\n"
               f"🚗 {entrada['km']} km")
    if es_nuevo:
        resumen += "\n\n📁 Se ha creado un archivo nuevo. Usa esta misma contraseña en el dashboard web para verlo."
    datos.pop(chat_id, None)
    mostrar_menu(chat_id, resumen)


@bot.message_handler(commands=["finalizarcarga"])
@bot.message_handler(func=lambda m: m.text == BTN_FINALIZAR_CARGA)
def finalizar_carga_inicio(message):
    chat_id = message.chat.id
    if _password_bloqueada(chat_id):
        mostrar_menu(chat_id, f"🚫 Demasiados intentos fallidos. Espera {_minutos_restantes_bloqueo(chat_id)} min. antes de volver a intentarlo.")
        return
    datos[chat_id] = {}
    if EV_BACKUP_PASSWORD:
        datos[chat_id]["password"] = EV_BACKUP_PASSWORD
        _iniciar_finalizar_carga(message, EV_BACKUP_PASSWORD)
    else:
        msg = bot.send_message(chat_id, "🔑 Escribe la contraseña del dashboard para completar la carga de anoche.", reply_markup=teclado_cancelar())
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
    datos.setdefault(chat_id, {})["password"] = password
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
        mostrar_menu(chat_id, "📭 No hay ninguna carga de casa pendiente de añadir el % final. Usa '📒 Anotar carga (Dashboard)' para registrar una nueva.")
        datos.pop(chat_id, None)
        return
    pendiente = sorted(pendientes, key=lambda l: l.get("date", ""))[-1]
    datos[chat_id]["finalizarCargaId"] = pendiente.get("id")
    msg = bot.send_message(
        chat_id,
        f"🔋 La carga del {pendiente.get('date', '?')} empezó al {pendiente.get('socStart', 0)}%.\n\n"
        "¿Con qué % ha terminado la carga? (0-100)",
        reply_markup=teclado_cancelar(),
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
    password = estado.get("password")
    log_id = estado.get("finalizarCargaId")
    if log_id is None:
        mostrar_menu(chat_id, "⚠️ Esta operación ha caducado. Vuelve a pulsar '🌙➡️☀️ Añadir % final de anoche'.")
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

    percent_final = float(valor)
    percent_inicial = log.get("socStart", 0)
    capacidad = _capacidad_efectiva(app_data)
    kwh = round(capacidad * (percent_final - percent_inicial) / 100, 2)
    tarifa = _tarifa_para_hora(app_data, (log.get("date") or "T01:00").split("T")[-1])
    log["socEnd"] = percent_final
    log["kwh"] = max(kwh, 0)
    log["cost"] = round(max(kwh, 0) * tarifa, 2)
    log["pendingFinal"] = False

    try:
        guardar_datos(app_data, password)
    except Exception:
        logger.exception("Error guardando el % final de la carga")
        mostrar_menu(chat_id, "⚠️ No se pudo guardar el cambio en el archivo.")
        datos.pop(chat_id, None)
        return

    datos.pop(chat_id, None)
    tarifa_txt = "valle 🌙" if tarifa == (app_data.get("settings", {}).get("pNight") or 0.03) else "punta ☀️"
    mostrar_menu(
        chat_id,
        "✅ ¡Carga completada!\n\n"
        f"🔋 {percent_inicial}% ➜ {percent_final}%\n"
        f"⚡ {log['kwh']} kWh cargados (estimado según la capacidad de la batería)\n"
        f"💶 {log['cost']}€ (tarifa {tarifa_txt})\n"
        f"🚗 {log.get('km', 0)} km parciales · Odómetro: {log.get('odo', 0)} km",
    )


@bot.message_handler(commands=["vercargas"])
@bot.message_handler(func=lambda m: m.text == BTN_VER_CARGAS)
def ver_cargas_inicio(message):
    chat_id = message.chat.id
    if _password_bloqueada(chat_id):
        mostrar_menu(chat_id, f"🚫 Demasiados intentos fallidos. Espera {_minutos_restantes_bloqueo(chat_id)} min. antes de volver a intentarlo.")
        return
    datos[chat_id] = {}
    if EV_BACKUP_PASSWORD:
        mostrar_ultimas_cargas(message, EV_BACKUP_PASSWORD)
    else:
        msg = bot.send_message(chat_id, "🔑 Escribe la contraseña del dashboard para ver las últimas cargas.", reply_markup=teclado_cancelar())
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
    lineas = ["📊 *Últimas cargas guardadas:*", ""]
    for l in ultimas:
        lugar = "🏠 Casa" if l.get("type") == "home" else f"🛣️ {l.get('brand', 'Calle')}"
        lineas.append(f"• {l.get('date', '?')} — {lugar} — {l.get('kwh', 0)} kWh — {l.get('cost', 0)}€")
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
        datos.setdefault(chat_id, {})["password"] = EV_BACKUP_PASSWORD
        siguiente_callback(message, EV_BACKUP_PASSWORD)
    else:
        datos.setdefault(chat_id, {})["_next_password_cb"] = siguiente_callback
        msg = bot.send_message(
            chat_id,
            "🔑 Escribe la contraseña del archivo del dashboard.\n\n⚠️ Borraré tu mensaje después de leerlo.",
            reply_markup=teclado_cancelar(),
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
    datos[chat_id]["password"] = password
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
    _requiere_password(message, lambda m, pwd: preguntar_soh_obd(m))


def preguntar_soh_obd(message):
    msg = bot.send_message(message.chat.id, "🔋 ¿Qué SoH (salud de batería, en %) marca el OBD?\n\nEjemplo: 92.5", reply_markup=teclado_cancelar())
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
    msg = bot.send_message(message.chat.id, "🚗 ¿Cuántos km tiene el odómetro?\n\nEjemplo: 45000", reply_markup=teclado_cancelar())
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
    msg = bot.send_message(message.chat.id, "🔢 ¿Capacidad real en kWh? (Escribe 0 si no lo sabes)", reply_markup=teclado_cancelar())
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
    msg = bot.send_message(message.chat.id, "⚖️ ¿Desbalanceo en mV? (Escribe 0 si no lo sabes)", reply_markup=teclado_cancelar())
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
    msg = bot.send_message(message.chat.id, "🔁 ¿Cuántos ciclos de carga? (Escribe 0 si no lo sabes)", reply_markup=teclado_cancelar())
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
               f"🔋 SoH: {nuevo.get('soh', 0)}%\n"
               f"🚗 Odómetro: {nuevo.get('odo', 0)} km\n"
               f"🔢 Capacidad: {nuevo.get('cap', 0)} kWh\n"
               f"⚖️ Desbalanceo: {nuevo.get('mv', 0)} mV\n"
               f"🔁 Ciclos: {nuevo.get('cycles', 0)}\n\n"
               f"¿Guardo este registro?")
    t = InlineKeyboardMarkup()
    t.add(
        InlineKeyboardButton("✅ Guardar", callback_data="CO_OK"),
        InlineKeyboardButton("❌ Cancelar", callback_data="CO_NO"),
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
        "date": datetime.datetime.now().strftime("%Y-%m-%d"),
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

    resumen = (f"✅ ¡Registro de batería guardado!\n\n"
               f"🔋 SoH: {entrada['soh']}%\n"
               f"🚗 Odómetro: {entrada['odo']} km\n"
               f"🔢 Capacidad: {entrada['cap']} kWh")
    if es_nuevo:
        resumen += "\n\n📁 Se ha creado un archivo nuevo. Usa esta misma contraseña en el dashboard web para verlo."
    datos.pop(chat_id, None)
    mostrar_menu(chat_id, resumen)


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
    lineas = ["🔎 *Últimos registros de batería:*", ""]
    for o in ultimos:
        lineas.append(f"• {o.get('date', '?')} — SoH {o.get('soh', 0)}% — {o.get('odo', 0)} km — {o.get('cap', 0)} kWh")
    bot.send_message(chat_id, "\n".join(lineas), parse_mode="Markdown")
    mostrar_menu(chat_id)


# =========================================================================
# Editar / Borrar registros ya guardados (cargas y OBD) mediante botones inline
# =========================================================================

def teclado_gestion_root():
    t = InlineKeyboardMarkup()
    t.add(InlineKeyboardButton("🔌 Cargas", callback_data="gm_logs"))
    t.add(InlineKeyboardButton("🔋 Batería (OBD)", callback_data="gm_obd"))
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

CONFIG_CAMPOS = {
    "priceEV": "💰 Precio del eléctrico (€)",
    "priceICE": "⛽ Precio del equivalente en gasolina (€)",
    "efficiency": "⚡ Eficiencia (%)",
    "pDay": "☀️ Precio kWh en horario día (€)",
    "pNight": "🌙 Precio kWh en horario noche (€)",
    "iceLiters": "⛽ Consumo gasolina (L/100km)",
    "icePrice": "💶 Precio del litro de gasolina (€)",
    "homePower": "🔌 Potencia del cargador de casa (kW)",
}


def teclado_mas_opciones():
    t = InlineKeyboardMarkup()
    t.add(InlineKeyboardButton("📈 Resumen / Ahorro", callback_data="mo_resumen"))
    t.add(InlineKeyboardButton("⚙️ Configuración", callback_data="mo_config"))
    t.add(InlineKeyboardButton("🏷️ Preset tarifa Iberdrola", callback_data="mo_preset_iberdrola"))
    t.add(InlineKeyboardButton("⛽ Actualizar precio gasóleo (auto)", callback_data="mo_gasoil"))
    t.add(InlineKeyboardButton("📤 Exportar backup", callback_data="mo_exportar"))
    t.add(InlineKeyboardButton("📥 Cómo importar backup", callback_data="mo_importar_info"))
    t.add(InlineKeyboardButton("❌ Cerrar", callback_data="gm_close"))
    return t


@bot.message_handler(commands=["masopciones"])
@bot.message_handler(func=lambda m: m.text == BTN_MAS)
def mas_opciones_inicio(message):
    datos[message.chat.id] = {}
    _requiere_password(message, mostrar_menu_mas_opciones)


def mostrar_menu_mas_opciones(message, password):
    bot.send_message(message.chat.id, "⚙️ ¿Qué quieres hacer?", reply_markup=teclado_mas_opciones())


def mostrar_resumen(chat_id, app_data):
    settings = app_data.get("settings", {})
    logs = app_data.get("logs", [])
    obd = app_data.get("obd", [])

    total_kwh = sum(l.get("kwh", 0) for l in logs)
    total_coste_ev = sum(l.get("cost", 0) for l in logs)

    ice_liters = settings.get("iceLiters", 0) or 0
    # Usamos el precio real y actual del gasóleo (API oficial) para no depender de que el
    # usuario lo busque y lo actualice a mano; si falla, caemos al valor configurado.
    precio_gasoil_live, _ = _obtener_precio_gasoil_actual()
    ice_price = precio_gasoil_live if precio_gasoil_live is not None else (settings.get("icePrice", 0) or 0)
    nota_precio_gasoil = (
        f"⛽ Gasóleo A usado: {ice_price}€/L (media nacional actual, automático)"
        if precio_gasoil_live is not None else
        f"⛽ Gasóleo A usado: {ice_price}€/L (valor configurado manualmente)"
    )
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
        "📈 *Resumen del dashboard:*",
        "",
        f"🔋 Total cargado: {round(total_kwh, 2)} kWh en {len(logs)} cargas",
        f"💶 Gasto en electricidad: {round(total_coste_ev, 2)}€",
        f"⛽ Coste equivalente en gasolina: {round(coste_ice_equivalente, 2)}€",
        f"💰 Ahorro acumulado: {round(ahorro, 2)}€",
        f"📊 ROI del sobreprecio del eléctrico: {round(roi, 1)}%",
        f"🔋 SoH actual de la batería: {soh_texto}",
        f"🚗 Autonomía real estimada: {round(autonomia_real)} km",
        "",
        nota_precio_gasoil,
    ]
    bot.send_message(chat_id, "\n".join(lineas), parse_mode="Markdown")


def mostrar_configuracion(chat_id, app_data):
    settings = app_data.get("settings", {})
    lineas = ["⚙️ *Configuración actual:*", ""]
    t = InlineKeyboardMarkup()
    for clave, etiqueta in CONFIG_CAMPOS.items():
        valor = settings.get(clave, "—")
        lineas.append(f"• {etiqueta}: {valor}")
        t.add(InlineKeyboardButton(f"✏️ {etiqueta}", callback_data=f"cfg|{clave}"))
    t.add(InlineKeyboardButton("⬅️ Volver", callback_data="mo_back"))
    bot.send_message(chat_id, "\n".join(lineas), parse_mode="Markdown")
    bot.send_message(chat_id, "Pulsa un campo para cambiarlo:", reply_markup=t)


def _iniciar_edicion_config(chat_id, clave, password):
    if clave not in CONFIG_CAMPOS:
        bot.send_message(chat_id, "⚠️ Campo no reconocido.")
        return
    etiqueta = CONFIG_CAMPOS[clave]
    datos.setdefault(chat_id, {})["editConfig"] = clave
    datos[chat_id]["password"] = password
    msg = bot.send_message(chat_id, f"✏️ Escribe el nuevo valor para: {etiqueta}", reply_markup=teclado_cancelar())
    bot.register_next_step_handler(msg, recibir_valor_config)


def recibir_valor_config(message):
    if es_cancelacion(message):
        return
    chat_id = message.chat.id
    valor_txt = message.text.replace(',', '.').strip()
    if not _es_numero(valor_txt):
        msg = bot.send_message(chat_id, "🙈 Escribe solo un número, por ejemplo: 0.22", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, recibir_valor_config)
        return
    estado = datos.get(chat_id, {})
    clave = estado.get("editConfig")
    password = estado.get("password")
    if not clave:
        mostrar_menu(chat_id, "⚠️ La edición ha caducado. Vuelve a intentarlo desde '⚙️ Más opciones'.")
        datos.pop(chat_id, None)
        return
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
    app_data.setdefault("settings", {})[clave] = float(valor_txt)
    try:
        guardar_datos(app_data, password)
    except Exception:
        logger.exception("Error guardando configuración")
        mostrar_menu(chat_id, "⚠️ No se pudo guardar el cambio en el archivo.")
        datos.pop(chat_id, None)
        return
    datos.pop(chat_id, None)
    etiqueta = CONFIG_CAMPOS.get(clave, clave)
    mostrar_menu(chat_id, f"✅ {etiqueta} actualizado a {valor_txt}.")


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
        InlineKeyboardButton("✅ Sí, reemplazar", callback_data="imp_ok"),
        InlineKeyboardButton("❌ No", callback_data="imp_no"),
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
        InlineKeyboardButton("✅ Sí, borrar", callback_data=f"LDY|{log_id}"),
        InlineKeyboardButton("❌ No", callback_data=f"L|{log_id}"),
    )
    bot.send_message(chat_id, "⚠️ ¿Seguro que quieres borrar esta carga? No se puede deshacer.", reply_markup=t)


def _confirmar_borrado_obd(chat_id, obd_id):
    t = InlineKeyboardMarkup()
    t.add(
        InlineKeyboardButton("✅ Sí, borrar", callback_data=f"ODY|{obd_id}"),
        InlineKeyboardButton("❌ No", callback_data=f"O|{obd_id}"),
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
    if data == "CL_HORA":
        hora_actual = datos.get(chat_id, {}).get("nuevaCarga", {}).get("horaInicio", HORA_INICIO_CARGA_DEFECTO)
        msg = bot.send_message(
            chat_id,
            f"⏰ Escribe la nueva hora de INICIO de carga (formato HH:MM, actual: {hora_actual}):",
            reply_markup=teclado_cancelar(),
        )
        bot.register_next_step_handler(msg, recibir_nueva_hora_inicio_casa)
        return
    if data == "CO_OK":
        _guardar_obd_confirmado(chat_id)
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

    password = datos.get(chat_id, {}).get("password") or EV_BACKUP_PASSWORD
    if not password:
        bot.send_message(chat_id, "⚠️ Tu sesión ha caducado. Vuelve a pulsar '🗂️ Editar / Borrar registros' o '⚙️ Más opciones'.")
        return

    try:
        app_data, _ = cargar_datos(password)
    except CryptoJSError:
        _registrar_intento_fallido(chat_id)
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
        bot.send_message(chat_id, "⚙️ ¿Qué quieres hacer?", reply_markup=teclado_mas_opciones())
    elif data == "mo_resumen":
        mostrar_resumen(chat_id, app_data)
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
        settings["pDay"] = 0.22
        settings["pNight"] = 0.03
        try:
            guardar_datos(app_data, password)
            bot.send_message(chat_id, "✅ Tarifa Iberdrola aplicada: 0.22€/kWh día, 0.03€/kWh noche.")
        except Exception:
            logger.exception("Error guardando preset de tarifa")
            bot.send_message(chat_id, "⚠️ No se pudo guardar la tarifa.")
    elif data == "mo_gasoil":
        precio, es_nuevo = _obtener_precio_gasoil_actual()
        if precio is None:
            bot.send_message(chat_id, "⚠️ No he podido consultar el precio del gasóleo ahora mismo. Inténtalo más tarde.")
        else:
            anterior = app_data.get("settings", {}).get("icePrice")
            app_data.setdefault("settings", {})["icePrice"] = precio
            try:
                guardar_datos(app_data, password)
                origen = "consultado ahora" if es_nuevo else "de la última consulta (caché de unas horas)"
                bot.send_message(
                    chat_id,
                    f"⛽ Precio del gasóleo A actualizado a {precio}€/L ({origen}, media nacional de todas las gasolineras de España).\n\n"
                    f"Valor anterior: {anterior}€/L.",
                )
            except Exception:
                logger.exception("Error guardando el precio del gasóleo")
                bot.send_message(chat_id, "⚠️ No se pudo guardar el nuevo precio.")
    elif data.startswith("cfg|"):
        _iniciar_edicion_config(chat_id, data.split("|", 1)[1], password)
    elif data == "gm_logs":
        _listar_logs_inline(chat_id, app_data)
    elif data == "gm_obd":
        _listar_obd_inline(chat_id, app_data)
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
        try:
            guardar_datos(app_data, password)
            bot.send_message(chat_id, "🗑️ Carga borrada correctamente.")
        except Exception:
            logger.exception("Error borrando carga")
            bot.send_message(chat_id, "⚠️ No se pudo borrar la carga.")
    elif data.startswith("ODY|"):
        obd_id = data.split("|", 1)[1]
        app_data["obd"] = [o for o in app_data.get("obd", []) if str(o.get("id")) != str(obd_id)]
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
        datos.setdefault(chat_id, {})["editLog"] = {"id": log_id}
        datos[chat_id]["password"] = password
        msg = bot.send_message(chat_id, f"✏️ Editando carga del {log.get('date')}.\n\n🔋 Nuevos kWh (actual: {log.get('kwh', 0)}):", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, editar_log_kwh)
    elif data.startswith("OE|"):
        obd_id = data.split("|", 1)[1]
        obd = _buscar_por_id(app_data.get("obd", []), obd_id)
        if not obd:
            bot.send_message(chat_id, "⚠️ No se encontró el registro.")
            return
        datos.setdefault(chat_id, {})["editObd"] = {"id": obd_id}
        datos[chat_id]["password"] = password
        msg = bot.send_message(chat_id, f"✏️ Editando registro del {obd.get('date')}.\n\n🔋 Nuevo SoH % (actual: {obd.get('soh', 0)}):", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, editar_obd_soh)


def editar_log_kwh(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not valor.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, editar_log_kwh)
        return
    datos.setdefault(message.chat.id, {}).setdefault("editLog", {})["kwh"] = float(valor)
    msg = bot.send_message(message.chat.id, "💶 Nuevo coste total (€):", reply_markup=teclado_cancelar())
    bot.register_next_step_handler(msg, editar_log_cost)


def editar_log_cost(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not valor.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, editar_log_cost)
        return
    datos.setdefault(message.chat.id, {}).setdefault("editLog", {})["cost"] = float(valor)
    msg = bot.send_message(message.chat.id, "🚗 Nuevos km parciales:", reply_markup=teclado_cancelar())
    bot.register_next_step_handler(msg, editar_log_km)


def editar_log_km(message):
    if es_cancelacion(message):
        return
    valor = message.text.replace(',', '.').strip()
    if not valor.replace('.', '', 1).isdigit():
        msg = bot.send_message(message.chat.id, "🙈 Escribe solo el número.", reply_markup=teclado_cancelar())
        bot.register_next_step_handler(msg, editar_log_km)
        return
    datos.setdefault(message.chat.id, {}).setdefault("editLog", {})["km"] = float(valor)
    guardar_edicion_log(message)


def guardar_edicion_log(message):
    chat_id = message.chat.id
    estado = datos.get(chat_id, {})
    password = estado.get("password")
    edit = estado.get("editLog", {})

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

    log["kwh"] = edit.get("kwh", log.get("kwh"))
    log["cost"] = edit.get("cost", log.get("cost"))
    log["km"] = edit.get("km", log.get("km"))

    try:
        guardar_datos(app_data, password)
    except Exception:
        logger.exception("Error guardando edición de carga")
        mostrar_menu(chat_id, "⚠️ No se pudo guardar el cambio en el archivo.")
        datos.pop(chat_id, None)
        return

    datos.pop(chat_id, None)
    mostrar_menu(chat_id, f"✅ Carga actualizada: {log['kwh']} kWh, {log['cost']}€, {log['km']} km.")


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
    bot.infinity_polling(skip_pending=True, timeout=20, long_polling_timeout=20)
    logger.info('Fin de la ejecución')
