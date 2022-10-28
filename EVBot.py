# -*- coding: utf-8 -*-

from config import *
import telebot
from telebot.types import ReplyKeyboardMarkup
from telebot.types import ForceReply

bot = telebot.TeleBot(TELEGRAM_TOKEN)
PRECIO_KWH_CASA=0.18
PORCENTAJE_BASE = 2.0
KWH_BASE = 1.0
datos = {}

@bot.message_handler(commands=["start", "ayuda"])
def start(message):
	bot.reply_to(message, """BIENVENIDO, AQUÍ TIENES ALGUNA DE LAS OPCIONES DISPONIBLES

- /start o /ayuda : Te enviará este mismo mensaje.
- /equivalencias : Te dirá las equivalencias de energía (Batería, kWh y KM).
- /recarga: Te hará una serie de preguntas para saber cuanto te costará la recarga.
""")
@bot.message_handler(commands=["equivalencias"])
def equivalencias(message):
	bot.reply_to(message, """BATERÍA Y SUS EQUIVALENCIAS (SITUACIÓN NORMAL)

- 2% >> 5km >> 1kWh
- 10% >> 25km >> 5kWh
- 25% >> 62,50km >> 12,50kWh
- 32% >> 80km >> 16kWh
- 40% >> 100km >> 20kWh
- 60% >> 150km >> 30kWh
- 80% >> 200km >> 40kWh
- 100% >> 250km >> 50kWh""")

@bot.message_handler(commands=["recarga"])
def recarga(message): 
    markup = ForceReply()
    msg = bot.send_message(message.chat.id, "¿QUÉ PORCENTAJE DE BATERÍA VAS HA RECARGAR?", reply_markup=markup)
    bot.register_next_step_handler(msg, porcentajeBateria)

def porcentajeBateria(message):
    datos[message.chat.id] = {}
    bateriaPorRecargar=message.text.replace(',','.')
    datos[message.chat.id]["bateriaPorRecargar"] = float(bateriaPorRecargar)
    if not bateriaPorRecargar.isnumeric():
        markup = ForceReply()
        msg = bot.send_message(message.chat.id, "ERROR: Debes indicar sólo un número sin decimales. ¿CUANTO PORCENTAJE DE BATERÍA VAS HA RECARGAR?", reply_markup=markup)
        bot.register_next_step_handler(msg, porcentajeBateria)
    else:
        markup = ReplyKeyboardMarkup(one_time_keyboard=True, input_field_placeholder="Pulsa un botón",resize_keyboard=True)
        markup.add("En Casa", "En la calle")
        msg = bot.send_message(message.chat.id, "¿DÓNDE VAS HA RECARGAR?", reply_markup=markup)
        bot.register_next_step_handler(msg, dondeRecarga)

def dondeRecarga(message):
    if message.text != "En Casa" and message.text != "En la calle":
        msg = bot.send_message(message.chat.id, "ERROR: Opción errónea, pulsa un botón", reply_markup=markup)
        bot.register_next_step_handler(msg, dondeRecarga)
    else:
        datos[message.chat.id]["lugarRecarga"] = message.text
        if datos[message.chat.id]["lugarRecarga"] == "En la calle":
            markup = ForceReply()
            msg = bot.send_message(message.chat.id, "¿A cuantos Euros esta por kWh?", reply_markup=markup)
            bot.register_next_step_handler(msg, precioKwhCalle)
        elif datos[message.chat.id]["lugarRecarga"] == "En Casa":
            calcularPrecioRecarga(message)

def precioKwhCalle(message):
    precioKwhCalle=message.text.replace(',','.')
    datos[message.chat.id]["precioKwhCalle"] = float(precioKwhCalle)
    if not precioKwhCalle.replace('.','',1).isdigit():
        markup = ForceReply()
        msg = bot.send_message(message.chat.id, "ERROR: Debes indicar sólo un número. ¿A cuantos Euros esta por kWh?", reply_markup=markup)
        bot.register_next_step_handler(msg, precioKwhCalle)
    else:
        calcularPrecioRecarga(message)

def calcularPrecioRecarga(message):
        kwhPorRecargar=datos[message.chat.id]["bateriaPorRecargar"] * KWH_BASE / PORCENTAJE_BASE
        if datos[message.chat.id]["lugarRecarga"] == "En la calle":
            precioRecarga = kwhPorRecargar*datos[message.chat.id]["precioKwhCalle"]
            precioRecargaCasa = kwhPorRecargar*PRECIO_KWH_CASA
            diferenciaDePrecio=precioRecarga-precioRecargaCasa
            msg = f"Esta misma recarga en casa te hubiera salido por {round(precioRecargaCasa,2)}€ aprox. Una diferencia de {round(diferenciaDePrecio,2)}€ aprox"
            bot.send_message(message.chat.id, msg)
        elif datos[message.chat.id]["lugarRecarga"] == "En Casa":
            precioRecarga = kwhPorRecargar*PRECIO_KWH_CASA
        msg2 = f"La recarga saldría por {round(precioRecarga,2)}€ aprox. habiendo hecho una recarga de {round(kwhPorRecargar,2)}kWh aprox."
        bot.send_message(message.chat.id, msg2)
        print(datos)


if __name__=='__main__':
    print('Iniciando EVBot')
    bot.infinity_polling()
    print('Fin de la ejecución')