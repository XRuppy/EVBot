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
import os
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


# Misma estructura por defecto que "defaultData" en ev_manager.html
DEFAULT_APP_DATA = {
    "settings": {
        "model": "Opel Mokka-e", "capacity": 46, "wltp": 332, "efficiency": 80,
        "priceEV": 32000, "priceICE": 22000, "iceLiters": 5.8, "icePrice": 1.50,
        "pDay": 0.22, "pNight": 0.03, "homePower": 4.4,
        "city": "", "provincia": "",
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


# =========================================================================
# Selector de fecha/hora (calendario + ajuste de hora por botones).
# La fecha/hora de inicio y fin de una carga NUNCA se debe asumir automáticamente como "ahora":
# se puede anotar una carga antes de que empiece, o completar los datos que faltan mucho después
# de que la carga haya terminado, y el momento en que se escribe en el bot no tiene por qué
# coincidir con el momento real en que la carga empezó o terminó. Por eso se pregunta siempre de
# forma explícita, pero con botones (calendario + spinner de hora) en vez de tener que escribirla
# a mano, para evitar errores de formato. "Usar fecha y hora actuales" sigue siendo un atajo de
# un solo toque para el caso normal (anotar justo en el momento).
# =========================================================================

MESES_ES = ["", "enero", "febrero", "marzo", "abril", "mayo", "junio", "julio",
            "agosto", "septiembre", "octubre", "noviembre", "diciembre"]

DTPICKER_PREGUNTAS = {
    "H_INI": "¿Cuándo empezaste a cargar (enchufaste el coche)?",
    "H_FIN": "¿Cuándo terminó realmente la carga?",
    "S_INI": "¿Cuándo empezaste a cargar?",
    "S_FIN": "¿Cuándo terminaste de cargar?",
    "OBD": "¿Qué día hiciste esta lectura de batería (OBD)?",
}

# Contextos que solo necesitan un DÍA (sin hora): el registro OBD, igual que su campo
# equivalente <input type="date"> en ev_manager.html, no guarda hora, solo fecha.
CTX_SOLO_FECHA = {"OBD"}


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


def _dtpicker_estado(chat_id):
    return datos.setdefault(chat_id, {}).setdefault("_dtpicker", {})


def _dtpicker_teclado_calendario(year, month, ctx):
    t = InlineKeyboardMarkup()
    etiqueta_ahora = "🕐 Usar fecha de hoy" if ctx in CTX_SOLO_FECHA else "🕐 Usar fecha y hora actuales"
    t.add(InlineKeyboardButton(etiqueta_ahora, callback_data=f"dtp|{ctx}|now"))
    t.add(
        InlineKeyboardButton("◀️", callback_data=f"dtp|{ctx}|nav|-1"),
        InlineKeyboardButton(f"{MESES_ES[month]} {year}", callback_data=f"dtp|{ctx}|noop"),
        InlineKeyboardButton("▶️", callback_data=f"dtp|{ctx}|nav|1"),
    )
    hoy = datetime.date.today()
    for semana in calendar.monthcalendar(year, month):
        fila = []
        for dia in semana:
            if dia == 0:
                fila.append(InlineKeyboardButton(" ", callback_data=f"dtp|{ctx}|noop"))
            else:
                marca = " •" if (year, month, dia) == (hoy.year, hoy.month, hoy.day) else ""
                fila.append(InlineKeyboardButton(f"{dia}{marca}", callback_data=f"dtp|{ctx}|day|{dia}"))
        t.add(*fila)
    t.add(_boton_inline("❌ Cancelar", f"dtp|{ctx}|cancel", ESTILO_PELIGRO))
    return t


def _dtpicker_teclado_hora(hour, minute, ctx):
    t = InlineKeyboardMarkup()
    t.add(
        InlineKeyboardButton("−1h", callback_data=f"dtp|{ctx}|h|-1"),
        InlineKeyboardButton(f"{hour:02d}:{minute:02d}", callback_data=f"dtp|{ctx}|noop"),
        InlineKeyboardButton("+1h", callback_data=f"dtp|{ctx}|h|1"),
    )
    t.add(
        InlineKeyboardButton("−30min", callback_data=f"dtp|{ctx}|m|-30"),
        InlineKeyboardButton("+30min", callback_data=f"dtp|{ctx}|m|30"),
    )
    t.add(
        InlineKeyboardButton("−5min", callback_data=f"dtp|{ctx}|m|-5"),
        InlineKeyboardButton("+5min", callback_data=f"dtp|{ctx}|m|5"),
    )
    t.add(_boton_inline("✅ Confirmar", f"dtp|{ctx}|ok", ESTILO_EXITO))
    t.add(InlineKeyboardButton("⬅️ Cambiar fecha", callback_data=f"dtp|{ctx}|back"))
    t.add(_boton_inline("❌ Cancelar", f"dtp|{ctx}|cancel", ESTILO_PELIGRO))
    return t


def _dtpicker_texto(ctx, estado):
    if ctx.startswith("EDITLOG_"):
        campo = ctx[len("EDITLOG_"):]
        etiqueta_campo = {"date": "fecha/hora de INICIO", "dateEnd": "fecha/hora de FIN"}.get(campo, campo)
        pregunta = f"Editando la {etiqueta_campo} de esta carga."
    else:
        pregunta = DTPICKER_PREGUNTAS.get(ctx.replace("_EDIT", ""), "¿Cuándo?")
    if estado.get("screen") == "hora":
        return (
            f"📅⏰ {pregunta}\n\n"
            f"Fecha elegida: {estado['day']:02d}/{estado['month']:02d}/{estado['year']}\n"
            "Ajusta la hora con los botones y confirma:"
        )
    if ctx in CTX_SOLO_FECHA:
        return f"📅 {pregunta}\n\nElige un día del calendario, o usa la fecha de hoy:"
    return f"📅⏰ {pregunta}\n\nElige un día del calendario, o usa la fecha/hora actuales:"


def iniciar_selector_fecha_hora(chat_id, ctx, valor_inicial_iso=None):
    """Abre el selector de fecha/hora (calendario + ajuste de hora con botones) para el contexto
    indicado (H_INI, H_FIN, S_INI, S_FIN). Por defecto parte del momento actual, salvo que se
    indique un valor previo (p.ej. al reeditar una fecha ya elegida)."""
    ahora = datetime.datetime.now()
    dt = ahora
    if valor_inicial_iso:
        try:
            dt = datetime.datetime.strptime(valor_inicial_iso, "%Y-%m-%dT%H:%M")
        except ValueError:
            dt = ahora
    estado = _dtpicker_estado(chat_id)
    estado.clear()
    estado.update({"ctx": ctx, "year": dt.year, "month": dt.month, "day": dt.day,
                   "hour": dt.hour, "minute": dt.minute, "screen": "cal"})
    texto = _dtpicker_texto(ctx, estado)
    teclado = _dtpicker_teclado_calendario(dt.year, dt.month, ctx)
    msg = bot.send_message(chat_id, texto, reply_markup=teclado)
    estado["msg_id"] = msg.message_id


def _dtpicker_refrescar(chat_id, call):
    estado = _dtpicker_estado(chat_id)
    ctx = estado.get("ctx", "")
    texto = _dtpicker_texto(ctx, estado)
    if estado.get("screen") == "hora":
        teclado = _dtpicker_teclado_hora(estado["hour"], estado["minute"], ctx)
    else:
        teclado = _dtpicker_teclado_calendario(estado["year"], estado["month"], ctx)
    try:
        bot.edit_message_text(texto, chat_id=chat_id, message_id=call.message.message_id, reply_markup=teclado)
    except Exception:
        pass  # p.ej. doble clic sobre el mismo botón: el contenido no cambia, no es un error real


def _confirmar_seleccion_fecha(chat_id, call, ctx, estado):
    if ctx in CTX_SOLO_FECHA:
        iso = f"{estado['year']:04d}-{estado['month']:02d}-{estado['day']:02d}"
        etiqueta = _formatear_fecha_solo(iso)
        texto_ok = f"✅ Fecha elegida: {etiqueta}"
    else:
        iso = f"{estado['year']:04d}-{estado['month']:02d}-{estado['day']:02d}T{estado['hour']:02d}:{estado['minute']:02d}"
        etiqueta = _formatear_fecha_hora(iso)
        texto_ok = f"✅ Fecha/hora elegida: {etiqueta}"
    datos.get(chat_id, {}).pop("_dtpicker", None)
    try:
        bot.edit_message_text(texto_ok, chat_id=chat_id, message_id=call.message.message_id)
    except Exception:
        pass

    if ctx == "H_INI":
        nueva = datos.setdefault(chat_id, {}).setdefault("nuevaCarga", {})
        nueva["fechaInicio"] = iso
        msg = bot.send_message(
            chat_id,
            "🔋 ¿Con qué % de batería has enchufado el coche?\n\nEjemplo: 35",
            reply_markup=teclado_cancelar(),
        )
        bot.register_next_step_handler(msg, recibir_percent_inicial_casa)
    elif ctx == "H_INI_EDIT":
        nueva = datos.setdefault(chat_id, {}).setdefault("nuevaCarga", {})
        nueva["fechaInicio"] = iso
        mostrar_confirmacion_carga_casa(call.message)
    elif ctx == "S_INI":
        nueva = datos.setdefault(chat_id, {}).setdefault("nuevaCarga", {})
        nueva["fechaInicio"] = iso
        msg = bot.send_message(chat_id, "🔋 ¿Cuántos kWh has cargado?\n\nEjemplo: 25.5", reply_markup=teclado_cancelar("Solo el número, ej: 25.5"))
        bot.register_next_step_handler(msg, recibir_kwh_carga)
    elif ctx == "S_INI_EDIT":
        nueva = datos.setdefault(chat_id, {}).setdefault("nuevaCarga", {})
        nueva["fechaInicio"] = iso
        mostrar_confirmacion_carga(call.message)
    elif ctx == "S_FIN":
        nueva = datos.setdefault(chat_id, {}).setdefault("nuevaCarga", {})
        nueva["fechaFin"] = iso
        mostrar_menu_avanzado_street(call.message)
    elif ctx == "S_FIN_EDIT":
        nueva = datos.setdefault(chat_id, {}).setdefault("nuevaCarga", {})
        nueva["fechaFin"] = iso
        mostrar_confirmacion_carga(call.message)
    elif ctx == "H_FIN":
        _completar_carga_pendiente(chat_id, iso)
    elif ctx == "OBD":
        nuevo = datos.setdefault(chat_id, {}).setdefault("nuevoObd", {})
        nuevo["fecha"] = iso
        preguntar_soh_obd(call.message)
    elif ctx.startswith("EDITLOG_"):
        key = ctx[len("EDITLOG_"):]
        datos.setdefault(chat_id, {}).setdefault("editLog", {}).setdefault("overrides", {})[key] = iso
        mostrar_menu_editar_log(chat_id)


def _manejar_callback_selector_fecha(call):
    chat_id = call.message.chat.id
    partes = call.data.split("|")
    _, ctx, accion, *resto = partes
    estado = _dtpicker_estado(chat_id)
    if estado.get("ctx") != ctx:
        estado["ctx"] = ctx

    if accion == "cancel":
        datos.pop(chat_id, None)
        try:
            bot.edit_message_text("❌ Cancelado.", chat_id=chat_id, message_id=call.message.message_id)
        except Exception:
            pass
        mostrar_menu(chat_id, "Vale, lo dejamos aquí. 😊")
        return

    if accion == "noop":
        return

    if accion == "nav":
        delta = int(resto[0])
        year, month = estado["year"], estado["month"]
        month += delta
        if month == 0:
            month, year = 12, year - 1
        elif month == 13:
            month, year = 1, year + 1
        dias_mes = calendar.monthrange(year, month)[1]
        estado["year"], estado["month"] = year, month
        estado["day"] = min(estado["day"], dias_mes)
        _dtpicker_refrescar(chat_id, call)
        return

    if accion == "day":
        estado["day"] = int(resto[0])
        if ctx in CTX_SOLO_FECHA:
            _confirmar_seleccion_fecha(chat_id, call, ctx, estado)
        else:
            estado["screen"] = "hora"
            _dtpicker_refrescar(chat_id, call)
        return

    if accion == "back":
        estado["screen"] = "cal"
        _dtpicker_refrescar(chat_id, call)
        return

    if accion in ("h", "m"):
        delta = int(resto[0])
        dt = datetime.datetime(estado["year"], estado["month"], estado["day"], estado["hour"], estado["minute"])
        dt += datetime.timedelta(hours=delta) if accion == "h" else datetime.timedelta(minutes=delta)
        estado.update({"year": dt.year, "month": dt.month, "day": dt.day, "hour": dt.hour, "minute": dt.minute})
        _dtpicker_refrescar(chat_id, call)
        return

    if accion == "now":
        ahora = datetime.datetime.now()
        estado.update({"year": ahora.year, "month": ahora.month, "day": ahora.day,
                       "hour": ahora.hour, "minute": ahora.minute})
        _confirmar_seleccion_fecha(chat_id, call, ctx, estado)
        return

    if accion == "ok":
        _confirmar_seleccion_fecha(chat_id, call, ctx, estado)
        return


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


_precio_gasoil_cache = {}  # clave: id de provincia o "NACIONAL" -> {"valor":.., "ts":.., "fuente":..}
PRECIO_GASOIL_CACHE_HORAS = 6

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


def _obtener_precio_gasoil_actual(provincia=None):
    """Consulta el precio medio actual del Gasóleo A en España (API abierta oficial del Gobierno,
    Ministerio para la Transición Ecológica) para no depender de que el usuario lo busque a mano.
    Si se indica `provincia` (nombre) y se reconoce, calcula la media solo de esa provincia; si no,
    usa la media nacional. Devuelve (precio, es_nuevo, descripcion_fuente) o (None, False, None) si
    nunca se pudo obtener. Cachea unas horas para no descargar el listado en cada consulta."""
    id_provincia = _obtener_id_provincia(provincia) if provincia else None
    clave_cache = id_provincia or "NACIONAL"
    ahora = datetime.datetime.now()
    cache = _precio_gasoil_cache.setdefault(clave_cache, {"valor": None, "ts": None, "fuente": None})
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
            valor_txt = (estacion.get("Precio Gasoleo A") or "").strip()
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
            f"media de {len(precios)} gasolineras, {provincia}"
            if id_provincia else
            f"media de {len(precios)} gasolineras"
        )
        cache["valor"] = media
        cache["ts"] = ahora
        cache["fuente"] = fuente
        return media, True, fuente
    except Exception:
        logger.exception("No se pudo obtener el precio del gasóleo A actual (se usará el último conocido o el configurado)")
        return cache["valor"], False, cache["fuente"]


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
BTN_VER_OBD = "🔎 Ver OBD"
BTN_GESTIONAR = "🗂️ Editar / Borrar"
BTN_MAS = "⚙️ Más opciones"
BTN_FINALIZAR_CARGA = "🌙 % final de anoche"

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
    teclado.add(BTN_OBD_ANOTAR, BTN_GESTIONAR)
    teclado.add(BTN_VER_CARGAS, BTN_VER_OBD)
    teclado.add(BTN_RECARGA, BTN_TIEMPO)
    teclado.add(BTN_RAPIDA22, BTN_RAPIDA55)
    teclado.add(BTN_MAS, BTN_EQUIVALENCIAS)
    teclado.add(BTN_AYUDA)
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
        "🌙 % final de anoche\n"
        "     Cierra la carga de casa\n"
        "     del día anterior.\n"
        "🔧 Anotar OBD\n"
        "     Guarda la salud de la batería.\n"
        "🗂️ Editar / Borrar\n"
        "     Cambia o elimina lo ya guardado.\n"
        "\n"
        "*📊 CONSULTAR*\n"
        "📊 Ver cargas\n"
        "🔎 Ver OBD\n"
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
        "tarifas, precio del gasóleo y copias\n"
        "de seguridad.\n"
        "\n"
        "💡 Las fechas se eligen con calendario,\n"
        "nunca se dan por supuestas."
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


def _purgar_sesiones_caducadas():
    limite = datetime.datetime.now() - datetime.timedelta(minutes=SESSION_TTL_MINUTOS)
    for chat_id in list(datos.keys()):
        estado = datos.get(chat_id) or {}
        ts = estado.get("_ts")
        if ts and ts < limite:
            datos.pop(chat_id, None)
            logger.info("Sesión de chat_id=%s purgada por inactividad (más de %s min)", chat_id, SESSION_TTL_MINUTOS)


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
    ("finalizarcarga", "% final de anoche"),
    ("anotarobd", "Anotar lectura OBD"),
    ("vercargas", "Ver últimas cargas"),
    ("verobd", "Ver últimos OBD"),
    ("gestionar", "Editar o borrar"),
    ("recarga", "Calcular precio de carga"),
    ("tiempo", "Cuándo desenchufar"),
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
    if EV_BACKUP_PASSWORD:
        _set_password_sesion(chat_id, EV_BACKUP_PASSWORD)
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
    ciudad = settings.get("city")
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
            ciudad = _obtener_settings_cache(chat_id, password).get("city")
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
        # Rutina real: por la noche solo se conocen % inicial, km parciales y odómetro.
        # El % final (y por tanto kWh/coste) se añaden al día siguiente ya cargados.
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
    mostrar_menu_avanzado_home(message)


def mostrar_confirmacion_carga_casa(message):
    chat_id = message.chat.id
    nueva = datos.get(chat_id, {}).get("nuevaCarga", {})
    potencia = nueva.get("power", _auto_potencia_casa(chat_id))
    resumen = (
        "📋 *Resumen de la carga (casa, nocturna):*\n\n"
        f"🕐 Inicio: {_formatear_fecha_hora(nueva.get('fechaInicio'))} (editable)\n"
        f"🔋 % inicial: {nueva.get('socStart', 0)}%\n"
        f"🚗 Km parciales: {nueva.get('km', 0)} km\n"
        f"🛣️ Odómetro: {nueva.get('odo', 0)} km\n"
        f"⚡ Potencia: {potencia} kW{' (auto)' if 'power' not in nueva else ''}\n"
    )
    if "precond" in nueva:
        resumen += f"❄️ Precondicionamiento: {'Sí' if nueva['precond'] else 'No'}\n"
    if "temp" in nueva:
        resumen += f"🌡️ Temp. exterior: {nueva['temp']}°C\n"
    resumen += (
        "\n⏳ El % final, la fecha/hora real de fin, los kWh cargados y el coste se calculan "
        "mañana con '🌙➡️☀️ Añadir % final de anoche'.\n\n"
        "¿Guardo esta carga en el dashboard?"
    )
    t = InlineKeyboardMarkup()
    t.add(_boton_inline("✅ Guardar", "CL_OK", ESTILO_EXITO))
    t.add(InlineKeyboardButton("✏️ Cambiar inicio", callback_data="CL_FECHA"))
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
        # kWh y coste quedan pendientes hasta que se añada el % final (con su fecha/hora real) al
        # día siguiente. La fecha/hora de inicio es la elegida por el usuario con el selector,
        # nunca el momento en que se está rellenando el formulario.
        settings = app_data.get("settings", {})
        fecha_inicio = nueva.get("fechaInicio") or datetime.datetime.now().strftime("%Y-%m-%dT%H:%M")
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
            "pendingFinal": True,
        }
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
        detalle = (
            f"🌙 Carga de casa (pendiente de cerrar)\n"
            f"🕐 Inicio: {_formatear_fecha_hora(fecha_inicio)}\n"
            f"🔋 % inicial: {entrada['socStart']}%\n"
            f"🚗 Km parciales: {entrada['km']} km · Odómetro: {entrada['odo']} km"
        )
        resumen = (
            "✅ ¡Carga de esta noche guardada!\n\n"
            + detalle
            + "\n\n⏳ Cuando termine, usa '🌙➡️☀️ Añadir % final de anoche' para indicar el % final y "
            "la fecha/hora real de fin; los kWh y el coste se calculan solos."
        )
        if es_nuevo:
            resumen += "\n\n📁 Se ha creado un archivo nuevo. Usa esta misma contraseña en el dashboard web para verlo."
        datos.pop(chat_id, None)
        mostrar_menu(chat_id, resumen)
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
    if EV_BACKUP_PASSWORD:
        _set_password_sesion(chat_id, EV_BACKUP_PASSWORD)
        _iniciar_finalizar_carga(message, EV_BACKUP_PASSWORD)
    else:
        msg = bot.send_message(chat_id, "🔑 Escribe la contraseña del dashboard para completar la carga de anoche.", reply_markup=teclado_cancelar("Contraseña del dashboard"))
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
        mostrar_menu(chat_id, "📭 No hay ninguna carga de casa pendiente de añadir el % final. Usa '📒 Anotar carga (Dashboard)' para registrar una nueva.")
        datos.pop(chat_id, None)
        return
    pendiente = sorted(pendientes, key=lambda l: l.get("date", ""))[-1]
    datos[chat_id]["finalizarCargaId"] = pendiente.get("id")
    msg = bot.send_message(
        chat_id,
        f"🔋 La carga del {_formatear_fecha_hora(pendiente.get('date'))} empezó al {pendiente.get('socStart', 0)}%.\n\n"
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
    if estado.get("finalizarCargaId") is None:
        mostrar_menu(chat_id, "⚠️ Esta operación ha caducado. Vuelve a pulsar '🌙➡️☀️ Añadir % final de anoche'.")
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

    percent_inicial = log.get("socStart", 0)
    capacidad = _capacidad_efectiva(app_data)
    kwh = round(capacidad * (percent_final - percent_inicial) / 100, 2)
    tarifa = _tarifa_para_hora(app_data, (log.get("date") or "T01:00").split("T")[-1])
    log["socEnd"] = percent_final
    log["kwh"] = max(kwh, 0)
    log["cost"] = round(max(kwh, 0) * tarifa, 2)
    log["pendingFinal"] = False
    log["dateEnd"] = fecha_fin_iso
    try:
        inicio_dt = datetime.datetime.strptime(log["date"], "%Y-%m-%dT%H:%M")
        fin_dt = datetime.datetime.strptime(fecha_fin_iso, "%Y-%m-%dT%H:%M")
        log["duration"] = max(int((fin_dt - inicio_dt).total_seconds() // 60), 0)
    except Exception:
        pass

    try:
        guardar_datos(app_data, password)
    except Exception:
        logger.exception("Error guardando el % final de la carga")
        mostrar_menu(chat_id, "⚠️ No se pudo guardar el cambio en el archivo.")
        datos.pop(chat_id, None)
        return

    datos.pop(chat_id, None)
    tarifa_txt = "valle 🌙" if tarifa == (app_data.get("settings", {}).get("pNight") or 0.03) else "punta ☀️"
    detalle = (
        f"🌙 Carga de casa completada\n"
        f"🕐 Fin: {_formatear_fecha_hora(fecha_fin_iso)}\n"
        f"🔋 {percent_inicial}% ➜ {percent_final}%\n"
        f"⚡ {log['kwh']} kWh cargados (estimado según la capacidad de la batería)\n"
        f"💶 {log['cost']}€ (tarifa {tarifa_txt})\n"
        f"⏱️ Duración real: {log.get('duration', '?')} min\n"
        f"🚗 {log.get('km', 0)} km parciales · Odómetro: {log.get('odo', 0)} km"
    )
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
    if EV_BACKUP_PASSWORD:
        mostrar_ultimas_cargas(message, EV_BACKUP_PASSWORD)
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

# Cada campo: clave -> (etiqueta corta, tipo "num"/"text", unidad).
# La etiqueta va corta y la unidad separada porque en la pantalla de configuración el valor
# actual se pinta DENTRO del propio botón ("🔋 Capacidad: 50 kWh"); con etiquetas largas
# Telegram recortaría el texto en el móvil y no se vería el valor, que es lo importante.
CONFIG_CAMPOS = {
    "model": ("🚘 Modelo", "text", ""),
    "capacity": ("🔋 Capacidad", "num", " kWh"),
    "wltp": ("🛣️ Autonomía WLTP", "num", " km"),
    "priceEV": ("💰 Precio eléctrico", "num", " €"),
    "priceICE": ("⛽ Precio gasolina", "num", " €"),
    "efficiency": ("⚡ Eficiencia", "num", " %"),
    "pDay": ("☀️ kWh de día", "num", " €"),
    "pNight": ("🌙 kWh de noche", "num", " €"),
    "iceLiters": ("⛽ Consumo", "num", " L/100km"),
    "icePrice": ("💶 Litro gasolina", "num", " €"),
    "homePower": ("🔌 Cargador de casa", "num", " kW"),
    "city": ("📍 Ciudad", "text", ""),
    "provincia": ("🗺️ Provincia", "text", ""),
}


def teclado_mas_opciones():
    t = InlineKeyboardMarkup()
    t.add(InlineKeyboardButton("📈 Resumen y ahorro", callback_data="mo_resumen"))
    t.add(InlineKeyboardButton("📊 Estadísticas", callback_data="mo_stats"))
    t.add(InlineKeyboardButton("⚙️ Configuración", callback_data="mo_config"))
    t.add(InlineKeyboardButton("🏷️ Tarifa Iberdrola", callback_data="mo_preset_iberdrola"))
    t.add(InlineKeyboardButton("⛽ Actualizar gasóleo", callback_data="mo_gasoil"))
    t.add(InlineKeyboardButton("📤 Exportar backup", callback_data="mo_exportar"))
    t.add(InlineKeyboardButton("📥 Cómo importar", callback_data="mo_importar_info"))
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
    # Usamos el precio real y actual del gasóleo (API oficial, por provincia si está configurada
    # en ⚙️ Configuración) para no depender de que el usuario lo busque y lo actualice a mano;
    # si falla, caemos al valor configurado.
    precio_gasoil_live, _, fuente_gasoil = _obtener_precio_gasoil_actual(settings.get("provincia"))
    ice_price = precio_gasoil_live if precio_gasoil_live is not None else (settings.get("icePrice", 0) or 0)
    nota_precio_gasoil = (
        f"⛽ Gasóleo: {ice_price} €/L\n_({fuente_gasoil})_"
        if precio_gasoil_live is not None else
        f"⛽ Gasóleo: {ice_price} €/L\n_(valor configurado a mano)_"
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
        "",
        "*Batería*",
        f"🔋 Salud (SoH): {soh_texto}",
        f"🚗 Autonomía real: {round(autonomia_real)} km",
        "",
        nota_precio_gasoil,
    ]
    bot.send_message(chat_id, "\n".join(lineas), parse_mode="Markdown")


def _texto_ahorro_carga(app_data, coste_ev, km):
    """Ahorro de UNA carga concreta frente al mismo coche pero de gasolina, usando el consumo
    (L/100km) configurado y el precio real y actual del gasóleo (por provincia si está
    configurada), igual criterio que el resumen global. Devuelve '' si no hay km para comparar."""
    if not km:
        return ""
    settings = app_data.get("settings", {})
    ice_liters = settings.get("iceLiters", 0) or 0
    precio_gasoil_live, _, fuente_gasoil = _obtener_precio_gasoil_actual(settings.get("provincia"))
    ice_price = precio_gasoil_live if precio_gasoil_live is not None else (settings.get("icePrice", 0) or 0)
    coste_ice = (km / 100) * ice_liters * ice_price
    ahorro = coste_ice - coste_ev
    return (
        f"\n\n💚 *Ahorro de esta carga: ~{round(ahorro, 2)} €*\n"
        f"En gasolina, esos {km} km\n"
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
    precio_gasoil_live, _, fuente_gasoil = _obtener_precio_gasoil_actual(settings.get("provincia"))
    ice_price = precio_gasoil_live if precio_gasoil_live is not None else (settings.get("icePrice", 0) or 0)

    # --- Uso y coste por año, con mix casa/calle ---
    por_anio = _resumen_logs_por_anio(logs)
    lineas_anio = ["📊 *Uso y coste por año*"]
    for anio in sorted(por_anio.keys()):
        d = por_anio[anio]
        coste_diesel_equiv = (d["km"] / 100) * ice_liters * ice_price if d["km"] else 0
        ahorro_anio = coste_diesel_equiv - d["cost"]
        lineas_anio.append("")
        lineas_anio.append(f"*{anio}*")
        lineas_anio.append(f"🔋 {round(d['kwh'], 1)} kWh   🚗 {round(d['km'])} km")
        lineas_anio.append(f"💶 {round(d['cost'], 2)} €   💰 ahorro {round(ahorro_anio, 2)} €")
        lineas_anio.append(f"🏠 {round(d['home_kwh'], 1)} kWh   🛣️ {round(d['street_kwh'], 1)} kWh")
    bot.send_message(chat_id, "\n".join(lineas_anio), parse_mode="Markdown")

    # --- Coste real €/100km vs diésel ---
    total_km = sum(l.get("km", 0) or 0 for l in logs)
    total_cost = sum(l.get("cost", 0) or 0 for l in logs)
    coste_100km_ev = (total_cost / total_km * 100) if total_km else None
    coste_100km_diesel = ice_liters * ice_price
    lineas_extra = ["⛽ *Coste real por 100 km*", ""]
    if coste_100km_ev is not None:
        lineas_extra.append(f"⚡ Eléctrico: {round(coste_100km_ev, 2)} €")
    else:
        lineas_extra.append("⚡ Eléctrico: aún sin km suficientes")
    lineas_extra.append(f"⛽ Diésel: {round(coste_100km_diesel, 2)} €")
    lineas_extra.append(f"_{ice_price} €/L_")
    lineas_extra.append(f"_{fuente_gasoil}_")

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
    t = InlineKeyboardMarkup()
    for clave, (etiqueta, _tipo, unidad) in CONFIG_CAMPOS.items():
        valor = settings.get(clave)
        if valor in (None, ""):
            texto_valor = "— sin definir"
        else:
            # Un valor de texto largo (p.ej. el modelo del coche) desbordaría el botón y
            # Telegram lo recortaría por su cuenta, escondiendo la unidad.
            texto_valor = str(valor)
            if len(texto_valor) > 16:
                texto_valor = texto_valor[:15] + "…"
            texto_valor = f"{texto_valor}{unidad}"
        t.add(InlineKeyboardButton(f"{etiqueta}: {texto_valor}", callback_data=f"cfg|{clave}"))
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
    datos.setdefault(chat_id, {})["editConfig"] = clave
    datos[chat_id]["editConfigTipo"] = tipo
    _set_password_sesion(chat_id, password)
    ejemplo = "Madrid" if tipo == "text" else "0.22"
    msg = bot.send_message(
        chat_id,
        f"✏️ *{etiqueta}*\n\nEscribe el nuevo valor.\nEjemplo: {ejemplo}",
        parse_mode="Markdown",
        reply_markup=teclado_cancelar(),
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
    # sigue interactuando (p.ej. navegando el calendario del selector de fecha/hora).
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
    if data.startswith("dtp|"):
        _manejar_callback_selector_fecha(call)
        return
    if data == "CO_OK":
        _guardar_obd_confirmado(chat_id)
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
        settings["pDay"] = 0.22
        settings["pNight"] = 0.03
        try:
            guardar_datos(app_data, password)
            bot.send_message(chat_id, "✅ Tarifa Iberdrola aplicada: 0.22€/kWh día, 0.03€/kWh noche.")
        except Exception:
            logger.exception("Error guardando preset de tarifa")
            bot.send_message(chat_id, "⚠️ No se pudo guardar la tarifa.")
    elif data == "mo_gasoil":
        provincia_settings = app_data.get("settings", {}).get("provincia")
        precio, es_nuevo, fuente_gasoil = _obtener_precio_gasoil_actual(provincia_settings)
        if precio is None:
            aviso_provincia = f" en la provincia '{provincia_settings}'" if provincia_settings else ""
            bot.send_message(chat_id, f"⚠️ No he podido consultar el precio del gasóleo{aviso_provincia} ahora mismo. Inténtalo más tarde.")
        else:
            anterior = app_data.get("settings", {}).get("icePrice")
            app_data.setdefault("settings", {})["icePrice"] = precio
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
                    f"⛽ Precio del gasóleo A actualizado a {precio}€/L ({fuente_gasoil}, {origen}).\n\n"
                    f"Valor anterior: {anterior}€/L." + consejo,
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


def _valor_mostrado_editar_log(chat_id, log, key, tipo):
    valor = _valor_actual_editar_log(chat_id, log, key)
    if valor is None or valor == "":
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
