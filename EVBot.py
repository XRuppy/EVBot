# -*- coding: utf-8 -*-

from config import *
#pip install pyTelegramBotAPI
import telebot
from telebot.types import ReplyKeyboardMarkup
from telebot.types import ForceReply
import datetime

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
- /tiempo: Te dará hora de desenchufar el cargador una vez enchufado e introducido los minutos de la carga.
- /tiempoRealCarga22kWh Te dará el tiempo real aproximado de carga a una velocidad de 22kWh
""")
@bot.message_handler(commands=["equivalencias"])
def equivalencias(message):
	bot.reply_to(message, """BATERÍA Y SUS EQUIVALENCIAS (SITUACIÓN NORMAL)

- 2% >> 5km >> 1kWh
- 10% >> 25km >> 5kWh
- 20% >> 50km >> 10kWh
- 25% >> 62,50km >> 12,50kWh
- 32% >> 80km >> 16kWh
- 40% >> 100km >> 20kWh
- 50% >> 125km >> 25kWh
- 60% >> 150km >> 30kWh
- 70% >> 175km >> 35kWh
- 80% >> 200km >> 40kWh
- 85% >> 212,50km >> 42,50kWh
- 100% >> 250km >> 50kWh""")

@bot.message_handler(commands=["recarga"])
def recarga(message): 
    markup = ForceReply()
    msg = bot.send_message(message.chat.id, "¿QUÉ PORCENTAJE DE BATERÍA VAS A RECARGAR?", reply_markup=markup)
    bot.register_next_step_handler(msg, porcentajeBateria)

def porcentajeBateria(message):
    datos[message.chat.id] = {}
    bateriaPorRecargar=message.text.replace(',','.')
    datos[message.chat.id]["bateriaPorRecargar"] = float(bateriaPorRecargar)
    if not bateriaPorRecargar.isnumeric():
        markup = ForceReply()
        msg = bot.send_message(message.chat.id, "ERROR: Debes indicar solo un número sin decimales. ¿CUÁNTO PORCENTAJE DE BATERÍA VAS A RECARGAR?", reply_markup=markup)
        bot.register_next_step_handler(msg, porcentajeBateria)
    else:
        markup = ReplyKeyboardMarkup(one_time_keyboard=True, input_field_placeholder="Pulsa un botón",resize_keyboard=True)
        markup.add("En Casa", "En la calle")
        msg = bot.send_message(message.chat.id, "¿DÓNDE VAS A RECARGAR?", reply_markup=markup)
        bot.register_next_step_handler(msg, dondeRecarga)

def dondeRecarga(message):
    if message.text != "En Casa" and message.text != "En la calle":
        msg = bot.send_message(message.chat.id, "ERROR: Opción errónea, pulsa un botón", reply_markup=markup)
        bot.register_next_step_handler(msg, dondeRecarga)
    else:
        datos[message.chat.id]["lugarRecarga"] = message.text
        if datos[message.chat.id]["lugarRecarga"] == "En la calle":
            markup = ForceReply()
            msg = bot.send_message(message.chat.id, "¿A cuántos Euros está por kWh?", reply_markup=markup)
            bot.register_next_step_handler(msg, precioKwhCalle)
        elif datos[message.chat.id]["lugarRecarga"] == "En Casa":
            calcularPrecioRecarga(message)

def precioKwhCalle(message):
    precioKwhCalle=message.text.replace(',','.')
    datos[message.chat.id]["precioKwhCalle"] = float(precioKwhCalle)
    if not precioKwhCalle.replace('.','',1).isdigit():
        markup = ForceReply()
        msg = bot.send_message(message.chat.id, "ERROR: Debes indicar solo un número. ¿A cuántos Euros está por kWh?", reply_markup=markup)
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

@bot.message_handler(commands=["tiempo"])
def recargaTiempo(message): 
    markup = ForceReply()
    msg = bot.send_message(message.chat.id, "¿Cuánto tiempo vas a recargar? (En Minutos)", reply_markup=markup)
    bot.register_next_step_handler(msg, calculoTiempoRecarga)

def calculoTiempoRecarga(message):
    minutosRecarga=message.text
    if not minutosRecarga.isdigit():
        markup = ForceReply()
        msg = bot.send_message(message.chat.id, "ERROR: Debes indicar solo números. ¿Cuántos minutos vas a recargar?", reply_markup=markup)
        bot.send_message(message.chat.id, msg)
    else:
        horaActual = datetime.datetime.now()
        horaFinalizacion = horaActual + datetime.timedelta(minutes=int(minutosRecarga))
        horaFinalString = str(horaFinalizacion.hour)+":"+str(horaFinalizacion.minute)
        print(horaActual.hour,":",horaActual.minute,sep='')
        print(horaFinalString)
        msg = f"Lo has enchufado a las {horaActual.hour}:{horaActual.minute}h por lo que la carga terminaría a las {horaFinalString}h"
        bot.send_message(message.chat.id, msg)


@bot.message_handler(commands=["tiempoRealCarga22kWh"])
def recargaTiempoReal(message): 
    markup = ForceReply()
    msg = bot.send_message(message.chat.id, "¿Qué porcentaje tiene actualmente?", reply_markup=markup)
    bot.register_next_step_handler(msg, calculoTiempoRecargaReal)

def calculoTiempoRecargaReal(message):
    porcentajeActual=message.text
    if not porcentajeActual.isdigit():
        markup = ForceReply()
        msg = bot.send_message(message.chat.id, "ERROR: Debes indicar solo números. ¿Qué porcentaje tiene actualmente?", reply_markup=markup)
        bot.send_message(message.chat.id, msg)
    else:
        porcentajeCarga =100 - int(porcentajeActual)
      # Porcentaje cargado en 93 minutos
        porcentaje1 = 14
        # Calculamos los minutos necesarios para llegar al porcentaje deseado
        minutos2 = (porcentajeCarga * 93) / porcentaje1 
        minutosRedondeados = round(minutos2)
        horaActual = datetime.datetime.now()
        horaFinalizacion = horaActual + datetime.timedelta(minutes=int(minutosRedondeados))
        horaFinalString = str(horaFinalizacion.hour)+":"+str(horaFinalizacion.minute)
        print(horaActual.hour,":",horaActual.minute,sep='')
        print(horaFinalString)
        horas = minutosRedondeados // 60
        minutos_restantes = minutosRedondeados % 60
        resultado = "{:02d}:{:02d}".format(horas, minutos_restantes)
        print(resultado)

        msg = f"Lo has enchufado a las {horaActual.hour}:{horaActual.minute}h por lo que la carga terminaría a las {horaFinalString}h. \n\nCargará un {porcentajeCarga}% hasta llegar al 100% y se estará {resultado} horas aprox."
        bot.send_message(message.chat.id, msg)

if __name__=='__main__':
    print('Iniciando EVBot')
    bot.infinity_polling()
    print('Fin de la ejecución')
