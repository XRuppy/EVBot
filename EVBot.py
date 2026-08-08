<!DOCTYPE html>
<html lang="es-ES">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <meta name="description" content="Gestor personal de vehículo eléctrico: recargas, costes, amortización y salud de la batería (OBD). Funciona en local, sin telemetría.">
    <meta name="color-scheme" content="light dark">
    <meta name="theme-color" content="#4f46e5">
    <meta name="referrer" content="no-referrer">

    <!--
      CSP: connect-src 'self' impide que un XSS exfiltre los datos a un servidor externo.
      'unsafe-inline' en script-src es necesario porque los <script> de este archivo son inline
      (es un HTML standalone). Al no quedar ni un solo manejador onclick="" en el marcado,
      se puede endurecer a hashes/nonce si algún día se sirve desde un backend.
      frame-ancestors NO funciona en <meta>: debe enviarse como cabecera HTTP desde el NAS.
    -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'">

    <title>EV Manager | Gestión de vehículo eléctrico</title>

    <script>
        // Tema inicial antes del primer pintado (evita parpadeo). En try/catch porque
        // localStorage lanza excepción si el navegador tiene el almacenamiento bloqueado.
        try {
            var temaGuardado = localStorage.getItem('theme');
            var prefiereOscuro = window.matchMedia('(prefers-color-scheme: dark)').matches;
            document.documentElement.classList.toggle('dark', temaGuardado === 'dark' || (temaGuardado === null && prefiereOscuro));
        } catch (e) { /* almacenamiento no disponible: se queda en claro */ }
    </script>

    <!-- Librerías externas. Versiones fijadas + SRI (integrity) + crossorigin.
         EXCEPCIÓN: cdn.tailwindcss.com NO envía cabeceras CORS, y sin CORS el
         navegador rechaza cualquier atributo integrity. Por eso este único script
         va sin SRI (verificado: la respuesta no trae Access-Control-Allow-Origin).
         Riesgo residual asumido. Mitigación recomendada para producción: compilar
         el CSS con la CLI de Tailwind y pegarlo en el <style> de este archivo;
         así desaparece la dependencia y la app funciona también sin internet.
         Hash SHA-512 de la versión 3.4.16 a fecha de la auditoría, por si se quiere
         verificar manualmente el fichero descargado:
         DSH9d7iZbrli7zjGLFXi+HPLpAi/ypa0xdWZCMoWVnadz0HKWbqvxNngwBkIVISAbp2WjaHFp2BCS+zAzLoRzw== -->
    <script src="https://cdn.tailwindcss.com/3.4.16" referrerpolicy="no-referrer"></script>
    <script>
        if (window.tailwind) {
            tailwind.config = {
                darkMode: 'class',
                theme: { extend: { fontFamily: { sans: ['Inter', 'Segoe UI', 'system-ui', 'sans-serif'] } } }
            };
        }
    </script>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.5.0/chart.umd.min.js"
            integrity="sha512-Y51n9mtKTVBh3Jbx5pZSJNDDMyY+yGe77DGtBPzRlgsf/YLCh13kSZ3JmfHGzYFCmOndraf0sQgfM654b7dJ3w=="
            crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js"
            integrity="sha512-a+SUDuwNzXDvz4XrIcXHuCf089/iJAoN4lmrXJg18XnduKK6YlDHNRalv4yd1N40OKI80tFidF+rqTFKGPoWFQ=="
            crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/css/all.min.css"
          integrity="sha512-Evv84Mr4kqVGRNSgIGL/F/aIDqQb7xQ2vcrdIwxfjThSH8CSR7PBEakCr51Ck+w+/U6swU2Im1vVX0SVk9ABhg=="
          crossorigin="anonymous" referrerpolicy="no-referrer">

    <style>
        /* Sin Google Fonts: evita filtrar la IP del usuario a Google (RGPD). Se usa Inter
           si está instalada en el sistema y, si no, la pila tipográfica nativa. */
        body { font-family: Inter, 'Segoe UI', Roboto, system-ui, -apple-system, 'Helvetica Neue', Arial, sans-serif; }

        /* Las utilidades de display de Tailwind (grid, flex…) ganan al atributo [hidden]
           del preflight. Sin esto, los paneles con `grid` seguirían visibles al ocultarlos. */
        [hidden] { display: none !important; }

        .glass { background: rgba(255,255,255,.85); backdrop-filter: blur(10px); border-bottom: 1px solid rgba(0,0,0,.06); }
        .dark .glass { background: rgba(15,23,42,.85); border-bottom: 1px solid rgba(255,255,255,.06); }

        .input-modern { background-color: transparent; border: 1px solid #cbd5e1; border-radius: .75rem; transition: border-color .2s, box-shadow .2s; }
        .dark .input-modern { border-color: #475569; color: #fff; }
        .input-modern:focus-visible { border-color: #4f46e5; box-shadow: 0 0 0 4px rgba(79,70,229,.18); outline: none; }
        .input-modern[aria-invalid="true"] { border-color: #dc2626; }
        .dark .input-modern[aria-invalid="true"] { border-color: #f87171; }

        /* Foco visible y coherente en todo el documento (navegación por teclado) */
        :where(button, [role="tab"], a, summary, input, select, textarea):focus-visible {
            outline: 3px solid #4f46e5; outline-offset: 2px; border-radius: .5rem;
        }
        .dark :where(button, [role="tab"], a, summary, input, select, textarea):focus-visible { outline-color: #a5b4fc; }

        .nav-link { position: relative; color: #475569; font-weight: 500; padding: 1rem .5rem; cursor: pointer; white-space: nowrap; background: none; border: 0; font-size: .875rem; }
        .dark .nav-link { color: #cbd5e1; }
        .nav-link[aria-selected="true"] { color: #4338ca; }
        .dark .nav-link[aria-selected="true"] { color: #a5b4fc; }
        .nav-link[aria-selected="true"]::after { content: ''; position: absolute; bottom: 0; left: 0; width: 100%; height: 3px; background: currentColor; border-radius: 3px 3px 0 0; }

        .no-scrollbar::-webkit-scrollbar { display: none; }
        .no-scrollbar { scrollbar-width: none; }

        .factor-card { transition: transform .2s ease; cursor: pointer; display: block; }
        .factor-card:hover { transform: translateY(-2px); }
        .factor-card input:checked + div { border-color: #4f46e5; background-color: rgba(79,70,229,.1); }
        .factor-card input:checked + div i { color: #4f46e5; }
        .factor-card input:focus-visible + div { outline: 3px solid #4f46e5; outline-offset: 2px; }

        .toggle-checkbox:checked + .toggle-bg { background-color: #4f46e5; }
        .toggle-checkbox:checked ~ .toggle-dot { transform: translateX(100%); }
        .toggle-checkbox:focus-visible + .toggle-bg { outline: 3px solid #4f46e5; outline-offset: 2px; }

        /* Los botones de acción de las tablas también aparecen al navegar con teclado */
        .row-actions { opacity: 0; transition: opacity .2s; }
        tr:hover .row-actions, tr:focus-within .row-actions { opacity: 1; }
        @media (hover: none) { .row-actions { opacity: 1; } }

        dialog::backdrop { background: rgba(0,0,0,.55); backdrop-filter: blur(4px); }
        dialog { border: 0; padding: 0; background: transparent; max-width: 100%; }

        .animate-fade-in { animation: fade-in .25s ease-out both; }
        @keyframes fade-in { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }

        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after { animation-duration: .001ms !important; transition-duration: .001ms !important; }
            .factor-card:hover { transform: none; }
        }

        .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
    </style>
</head>
<body class="bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-100 min-h-screen flex flex-col">

    <!-- Región viva para anuncios a lectores de pantalla -->
    <p id="live-region" class="sr-only" role="status" aria-live="polite"></p>

    <!-- Aviso emergente de guardado -->
    <div id="save-toast" class="fixed bottom-4 right-4 bg-slate-800 dark:bg-white text-white dark:text-slate-900 px-4 py-2 rounded-full shadow-lg text-xs font-bold translate-y-24 transition-transform duration-300 z-50 flex items-center gap-2 pointer-events-none">
        <i id="toast-icon" class="fa-solid fa-floppy-disk text-emerald-400" aria-hidden="true"></i>
        <span id="toast-msg">Guardado local</span>
    </div>

    <!-- Diálogo de seguridad (cifrado AES) -->
    <dialog id="security-modal" aria-labelledby="modal-title">
        <form method="dialog" class="bg-white dark:bg-slate-900 w-[min(28rem,92vw)] p-6 rounded-3xl shadow-2xl border border-slate-200 dark:border-slate-800 text-left">
            <div class="flex items-center gap-3 mb-4 text-indigo-700 dark:text-indigo-300">
                <i class="fa-solid fa-shield-halved text-2xl" aria-hidden="true"></i>
                <h2 class="text-xl font-bold text-slate-900 dark:text-white" id="modal-title">Seguridad</h2>
            </div>
            <p class="text-sm text-slate-600 dark:text-slate-300 mb-6" id="modal-desc">Introduce una contraseña para cifrar el archivo.</p>

            <div class="space-y-4">
                <div>
                    <label for="modal-pass" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1 block">Contraseña</label>
                    <div class="relative">
                        <input type="password" id="modal-pass" name="modal-pass" autocomplete="current-password"
                               class="input-modern w-full p-3 text-lg pr-12" placeholder="Mínimo 12 caracteres">
                        <button type="button" id="btn-toggle-pass" data-action="toggle-pass"
                                class="absolute right-2 top-2 w-9 h-9 rounded-lg text-slate-500 hover:text-indigo-600"
                                aria-label="Mostrar u ocultar la contraseña" aria-pressed="false">
                            <i class="fa-solid fa-eye" id="pass-eye-icon" aria-hidden="true"></i>
                        </button>
                    </div>
                    <p id="modal-pass-error" class="text-xs font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" role="alert"></p>
                </div>
                <div class="flex gap-3 pt-2">
                    <button type="button" data-action="close-security" class="flex-1 py-3 rounded-xl font-bold text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800">Cancelar</button>
                    <button type="button" id="modal-action-btn" data-action="confirm-security" class="flex-1 py-3 rounded-xl font-bold bg-indigo-600 text-white hover:bg-indigo-700 shadow-lg shadow-indigo-500/30">Confirmar</button>
                </div>
            </div>
        </form>
    </dialog>

    <!-- Diálogo de confirmación de borrado -->
    <dialog id="delete-modal" aria-labelledby="delete-title" aria-describedby="delete-desc">
        <div class="bg-white dark:bg-slate-900 w-[min(24rem,92vw)] p-6 rounded-3xl shadow-2xl border border-slate-200 dark:border-slate-800 text-center">
            <div class="w-12 h-12 bg-red-100 dark:bg-red-900/30 rounded-full flex items-center justify-center mx-auto mb-4 text-red-600 dark:text-red-400">
                <i class="fa-solid fa-trash-can text-xl" aria-hidden="true"></i>
            </div>
            <h2 class="text-lg font-bold text-slate-900 dark:text-white mb-2" id="delete-title">¿Borrar el registro?</h2>
            <p class="text-sm text-slate-600 dark:text-slate-300 mb-6" id="delete-desc">Esta acción no se puede deshacer.</p>
            <div class="flex gap-3">
                <button type="button" data-action="close-delete" class="flex-1 py-2.5 rounded-xl font-bold text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800">Cancelar</button>
                <button type="button" data-action="confirm-delete" class="flex-1 py-2.5 rounded-xl font-bold bg-red-600 text-white hover:bg-red-700 shadow-lg shadow-red-500/30">Eliminar</button>
            </div>
        </div>
    </dialog>

    <!-- Cabecera -->
    <header class="glass z-30 flex-none sticky top-0">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between items-center h-16 gap-3">
                <div class="flex items-center gap-3 min-w-0">
                    <div class="bg-gradient-to-br from-indigo-600 to-purple-700 w-10 h-10 rounded-xl flex items-center justify-center text-white shadow-lg flex-none"><i class="fa-solid fa-bolt" aria-hidden="true"></i></div>
                    <h1 class="font-bold text-xl tracking-tight truncate">EV Manager</h1>
                </div>
                <div class="flex items-center gap-2">
                    <button type="button" id="server-status" data-action="reload-server"
                            class="hidden sm:flex items-center gap-2 text-[11px] font-bold bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-300 px-3 py-1.5 rounded-full border border-emerald-200 dark:border-emerald-800 hover:bg-emerald-100 dark:hover:bg-emerald-900/40">
                        <i class="fa-solid fa-server" aria-hidden="true"></i> <span id="server-status-text">Recargar del NAS</span>
                    </button>
                    <button type="button" data-action="toggle-theme" id="btn-theme"
                            class="w-10 h-10 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center"
                            aria-label="Cambiar entre tema claro y oscuro">
                        <i class="fa-solid fa-sun block dark:hidden text-orange-500" aria-hidden="true"></i>
                        <i class="fa-solid fa-moon hidden dark:block text-indigo-300" aria-hidden="true"></i>
                    </button>
                </div>
            </div>
        </div>
    </header>

    <!-- Navegación -->
    <nav class="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 flex-none overflow-x-auto no-scrollbar" aria-label="Secciones">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex space-x-4 sm:space-x-6 items-center" role="tablist">
                <button type="button" role="tab" id="tab-dashboard"  aria-controls="view-dashboard"  aria-selected="true"  class="nav-link">Panel</button>
                <button type="button" role="tab" id="tab-calculator" aria-controls="view-calculator" aria-selected="false" tabindex="-1" class="nav-link">Calculadora</button>
                <button type="button" role="tab" id="tab-logs"       aria-controls="view-logs"       aria-selected="false" tabindex="-1" class="nav-link">Recargas</button>
                <button type="button" role="tab" id="tab-health"     aria-controls="view-health"     aria-selected="false" tabindex="-1" class="nav-link">Batería&nbsp;OBD</button>
                <button type="button" role="tab" id="tab-config"     aria-controls="view-config"     aria-selected="false" tabindex="-1" class="nav-link">Configuración</button>
            </div>
        </div>
    </nav>

    <main class="flex-1 p-4 sm:p-6 lg:p-8">
        <div class="max-w-7xl mx-auto space-y-8 pb-10">

            <!-- ==================== PANEL ==================== -->
            <section id="view-dashboard" role="tabpanel" aria-labelledby="tab-dashboard" tabindex="0" class="space-y-6 animate-fade-in">
                <h2 class="sr-only">Panel de control</h2>

                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div class="bg-white dark:bg-slate-900 p-5 rounded-3xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <p class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase" id="lbl-savings">Ahorro acumulado</p>
                        <p class="text-2xl font-black text-emerald-600 dark:text-emerald-400" id="kpi-savings" aria-labelledby="lbl-savings">0,00 €</p>
                    </div>
                    <div class="bg-indigo-600 p-5 rounded-3xl shadow-xl text-white">
                        <p class="text-[11px] font-bold text-indigo-100 uppercase" id="lbl-roi">Amortización (ROI)</p>
                        <p class="text-2xl font-black" id="kpi-roi" aria-labelledby="lbl-roi">0 %</p>
                        <div class="w-full bg-indigo-900 h-1.5 rounded-full mt-2 overflow-hidden" role="progressbar" id="roi-progress" aria-labelledby="lbl-roi" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
                            <div id="roi-bar" class="bg-white h-full transition-all duration-700" style="width:0%"></div>
                        </div>
                    </div>
                    <div class="bg-white dark:bg-slate-900 p-5 rounded-3xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <p class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase" id="lbl-soh">Salud actual (SoH)</p>
                        <p class="text-2xl font-black text-indigo-600 dark:text-indigo-400" id="kpi-soh" aria-labelledby="lbl-soh">—</p>
                    </div>
                    <div class="bg-white dark:bg-slate-900 p-5 rounded-3xl border border-slate-200 dark:border-slate-800 shadow-sm">
                        <p class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase" id="lbl-range">Autonomía real</p>
                        <p class="text-2xl font-black" id="kpi-range" aria-labelledby="lbl-range">—</p>
                        <p class="mt-1 text-[11px] text-slate-600 dark:text-slate-400" id="kpi-range-desc">Factor: 80 %</p>
                    </div>
                </div>

                <div class="bg-white dark:bg-slate-900 p-6 rounded-3xl border border-slate-200 dark:border-slate-800">
                    <div class="flex flex-wrap justify-between items-center gap-3 mb-4">
                        <h3 class="text-lg font-bold text-slate-800 dark:text-white">Evolución financiera</h3>
                        <div class="flex bg-slate-100 dark:bg-slate-800 rounded-lg p-1" role="group" aria-label="Modo de la gráfica">
                            <button type="button" data-action="chart-mode" data-mode="cumulative" id="btn-chart-cumulative" aria-pressed="true"  class="px-3 py-1 text-xs font-bold rounded-md bg-white dark:bg-slate-700 shadow-sm text-indigo-700 dark:text-white">Acumulado</button>
                            <button type="button" data-action="chart-mode" data-mode="annual"     id="btn-chart-annual"     aria-pressed="false" class="px-3 py-1 text-xs font-bold rounded-md text-slate-600 dark:text-slate-300">Anual</button>
                        </div>
                    </div>
                    <div class="h-80 w-full relative"><canvas id="chart-main" role="img" aria-label="Evolución del ahorro acumulado frente al vehículo de referencia"></canvas></div>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div class="bg-white dark:bg-slate-900 p-6 rounded-3xl border border-slate-200 dark:border-slate-800">
                        <h3 class="text-base font-bold text-slate-800 dark:text-white mb-6">Comparativa de costes anuales</h3>
                        <div class="h-64 w-full"><canvas id="chart-costs-annual" role="img" aria-label="Coste anual del eléctrico frente al vehículo de referencia"></canvas></div>
                    </div>
                    <div class="bg-white dark:bg-slate-900 p-6 rounded-3xl border border-slate-200 dark:border-slate-800">
                        <h3 class="text-base font-bold text-slate-800 dark:text-white mb-6">Rendimiento anual (km frente a kWh)</h3>
                        <div class="h-64 w-full"><canvas id="chart-usage-annual" role="img" aria-label="Kilómetros y energía consumida por año"></canvas></div>
                    </div>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div class="bg-white dark:bg-slate-900 p-6 rounded-3xl border border-slate-200 dark:border-slate-800">
                        <h3 class="text-base font-bold text-slate-800 dark:text-white mb-2">Mix energético anual (kWh)</h3>
                        <p class="text-xs text-slate-600 dark:text-slate-400 mb-6">Energía cargada en casa frente a pública, por año</p>
                        <div class="h-64 w-full"><canvas id="chart-location-annual" role="img" aria-label="Energía cargada en casa frente a pública por año"></canvas></div>
                    </div>
                    <div class="bg-white dark:bg-slate-900 p-6 rounded-3xl border border-slate-200 dark:border-slate-800">
                        <h3 class="text-base font-bold text-slate-800 dark:text-white mb-2">Operadores más usados (nº de cargas)</h3>
                        <p class="text-xs text-slate-600 dark:text-slate-400 mb-6">Reparto de tus recargas públicas</p>
                        <div class="h-64 w-full flex justify-center"><canvas id="chart-brands" role="img" aria-label="Reparto de recargas públicas por operador"></canvas></div>
                    </div>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div class="bg-white dark:bg-slate-900 p-6 rounded-3xl border border-slate-200 dark:border-slate-800">
                        <h3 class="text-base font-bold text-slate-800 dark:text-white mb-2">Coste real (€/100 km)</h3>
                        <p class="text-xs text-slate-600 dark:text-slate-400 mb-6">Tu eficiencia económica mensual frente al vehículo de referencia</p>
                        <div class="h-64 w-full"><canvas id="chart-cost-100km" role="img" aria-label="Coste por cada 100 kilómetros, mensual"></canvas></div>
                    </div>
                    <div class="bg-white dark:bg-slate-900 p-6 rounded-3xl border border-slate-200 dark:border-slate-800">
                        <h3 class="text-base font-bold text-slate-800 dark:text-white mb-2">Proyección de amortización</h3>
                        <p class="text-xs text-slate-600 dark:text-slate-400 mb-6" id="roi-prediction-text">Calculando…</p>
                        <div class="h-64 w-full"><canvas id="chart-roi-projection" role="img" aria-label="Proyección del ahorro acumulado hasta amortizar la inversión"></canvas></div>
                    </div>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div class="bg-white dark:bg-slate-900 p-6 rounded-3xl border border-slate-200 dark:border-slate-800 lg:col-span-2">
                        <h3 class="text-base font-bold text-slate-800 dark:text-white mb-2">Ranking de operadores (€/kWh real)</h3>
                        <p class="text-xs text-slate-600 dark:text-slate-400 mb-6">Coste final medio por operador, incluyendo costes fijos</p>
                        <div class="h-64 w-full"><canvas id="chart-operator-price" role="img" aria-label="Precio real por kilovatio hora de cada operador"></canvas></div>
                    </div>
                    <div class="bg-white dark:bg-slate-900 p-6 rounded-3xl border border-slate-200 dark:border-slate-800">
                        <h3 class="text-base font-bold text-slate-800 dark:text-white mb-2">Ciclos de carga (zona óptima 20-80 %)</h3>
                        <p class="text-xs text-slate-600 dark:text-slate-400 mb-6">Porcentaje de inicio y final de cada sesión</p>
                        <div class="h-64 w-full"><canvas id="chart-charging-health" role="img" aria-label="Rango de carga de cada sesión frente a la zona óptima"></canvas></div>
                    </div>
                    <div class="bg-white dark:bg-slate-900 p-6 rounded-3xl border border-slate-200 dark:border-slate-800">
                        <h3 class="text-base font-bold text-slate-800 dark:text-white mb-2">Rendimiento de carga (kW)</h3>
                        <p class="text-xs text-slate-600 dark:text-slate-400 mb-6">Potencia teórica del cargador frente a la real obtenida</p>
                        <div class="h-64 w-full"><canvas id="chart-charging-efficiency" role="img" aria-label="Potencia teórica frente a potencia real media de carga"></canvas></div>
                    </div>
                </div>
            </section>

            <!-- ==================== CALCULADORA ==================== -->
            <section id="view-calculator" role="tabpanel" aria-labelledby="tab-calculator" tabindex="0" hidden class="space-y-8 animate-fade-in">
                <h2 class="sr-only">Calculadora</h2>

                <div class="bg-white dark:bg-slate-900 p-6 sm:p-8 rounded-3xl border border-slate-200 dark:border-slate-800">
                    <div class="flex flex-wrap items-center justify-between gap-4 mb-6">
                        <h3 class="font-bold flex items-center gap-2"><i class="fa-regular fa-square-check text-indigo-500" aria-hidden="true"></i> Estimación y equivalencias</h3>
                        <label for="toggle-factors" class="flex items-center cursor-pointer">
                            <span class="relative inline-flex items-center">
                                <input type="checkbox" id="toggle-factors" class="sr-only toggle-checkbox" checked>
                                <span class="toggle-bg block bg-slate-300 dark:bg-slate-700 w-10 h-6 rounded-full transition-colors duration-300"></span>
                                <span class="toggle-dot absolute left-1 top-1 bg-white w-4 h-4 rounded-full shadow transition-transform duration-200"></span>
                            </span>
                            <span class="ml-3 text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Modo realista (OBD)</span>
                        </label>
                    </div>

                    <fieldset class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-8 border-0 p-0 m-0">
                        <legend class="sr-only">Factores que penalizan la autonomía</legend>
                        <label class="factor-card" for="calc-factor-wltp">
                            <input type="checkbox" id="calc-factor-wltp" class="sr-only" checked disabled>
                            <div class="p-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 flex flex-col items-center justify-center text-center h-20">
                                <i class="fa-regular fa-square-check mb-1 text-indigo-500" aria-hidden="true"></i>
                                <span class="text-[11px] font-bold uppercase text-slate-600 dark:text-slate-400" id="calc-factor-wltp-label">Base</span>
                            </div>
                        </label>
                        <label class="factor-card" for="calc-factor-ac">
                            <input type="checkbox" id="calc-factor-ac" class="sr-only">
                            <div class="p-3 rounded-xl border border-slate-200 dark:border-slate-700 flex flex-col items-center justify-center text-center h-20 hover:bg-slate-50 dark:hover:bg-slate-800/50">
                                <i class="fa-solid fa-fan mb-1 text-slate-500" aria-hidden="true"></i>
                                <span class="text-[11px] font-bold uppercase text-slate-600 dark:text-slate-400">Clima (−10 %)</span>
                            </div>
                        </label>
                        <label class="factor-card" for="calc-factor-highway">
                            <input type="checkbox" id="calc-factor-highway" class="sr-only">
                            <div class="p-3 rounded-xl border border-slate-200 dark:border-slate-700 flex flex-col items-center justify-center text-center h-20 hover:bg-slate-50 dark:hover:bg-slate-800/50">
                                <i class="fa-solid fa-road mb-1 text-slate-500" aria-hidden="true"></i>
                                <span class="text-[11px] font-bold uppercase text-slate-600 dark:text-slate-400">Autopista (−15 %)</span>
                            </div>
                        </label>
                        <label class="factor-card" for="calc-factor-cold">
                            <input type="checkbox" id="calc-factor-cold" class="sr-only">
                            <div class="p-3 rounded-xl border border-slate-200 dark:border-slate-700 flex flex-col items-center justify-center text-center h-20 hover:bg-slate-50 dark:hover:bg-slate-800/50">
                                <i class="fa-solid fa-temperature-arrow-down mb-1 text-slate-500" aria-hidden="true"></i>
                                <span class="text-[11px] font-bold uppercase text-slate-600 dark:text-slate-400">Frío ext. (−10 %)</span>
                            </div>
                        </label>
                    </fieldset>

                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div class="text-center">
                            <label for="calc-input-percent" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-2 block">Batería (%)</label>
                            <input type="number" id="calc-input-percent" value="50" min="0" max="100" step="1" inputmode="decimal"
                                   class="w-full text-center text-4xl font-black bg-transparent border-0 border-b-2 border-indigo-500 focus:outline-none py-2 text-slate-800 dark:text-white">
                        </div>
                        <div class="text-center">
                            <label for="calc-input-kwh" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-2 block">Energía (kWh)</label>
                            <input type="number" id="calc-input-kwh" min="0" step="0.1" inputmode="decimal" aria-describedby="calc-info-cap"
                                   class="w-full text-center text-4xl font-black bg-transparent border-0 border-b-2 border-slate-300 focus:outline-none py-2 text-slate-800 dark:text-white">
                            <p class="text-[11px] text-slate-600 dark:text-slate-400 mt-1" id="calc-info-cap">Capacidad nominal</p>
                        </div>
                        <div class="text-center">
                            <label for="calc-input-km" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-2 block">Alcance (km)</label>
                            <input type="number" id="calc-input-km" min="0" step="1" inputmode="decimal"
                                   class="w-full text-center text-4xl font-black bg-transparent border-0 border-b-2 border-emerald-500 focus:outline-none py-2 text-slate-800 dark:text-white">
                        </div>
                    </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div class="bg-white dark:bg-slate-900 p-6 sm:p-8 rounded-3xl border border-slate-200 dark:border-slate-800">
                        <h3 class="font-bold mb-6 flex items-center gap-2"><i class="fa-solid fa-plug-circle-bolt text-emerald-600" aria-hidden="true"></i> Simulador de curva de carga</h3>
                        <div class="grid grid-cols-2 gap-4 mb-6">
                            <div>
                                <label for="charge-start" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Inicio (%)</label>
                                <input type="number" id="charge-start" value="20" min="0" max="100" step="1" inputmode="decimal" class="input-modern w-full p-3 text-lg font-bold">
                            </div>
                            <div>
                                <label for="charge-end" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Final (%)</label>
                                <input type="number" id="charge-end" value="100" min="0" max="100" step="1" inputmode="decimal" class="input-modern w-full p-3 text-lg font-bold">
                            </div>
                            <div class="col-span-2">
                                <label for="charge-kw" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Potencia del cargador (kW)</label>
                                <input type="number" id="charge-kw" value="11" min="0.1" max="400" step="0.1" inputmode="decimal" class="input-modern w-full p-3 text-lg font-bold">
                            </div>
                        </div>
                        <div class="p-4 bg-slate-50 dark:bg-slate-800/50 rounded-2xl text-center">
                            <p class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1">Tiempo estimado</p>
                            <p class="text-3xl font-black text-indigo-700 dark:text-indigo-300" id="charge-full-res">0 h 0 min</p>
                            <p id="charge-net-power" class="text-[11px] text-slate-600 dark:text-slate-400 mt-2 font-bold uppercase"></p>
                        </div>
                    </div>
                    <div class="bg-white dark:bg-slate-900 p-6 sm:p-8 rounded-3xl border border-slate-200 dark:border-slate-800">
                        <h3 class="font-bold mb-6 flex items-center gap-2"><i class="fa-solid fa-battery-half text-indigo-600" aria-hidden="true"></i> Carga hasta el 80 % (saludable)</h3>
                        <div class="space-y-4">
                            <div>
                                <label for="calc80-input" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">SoC actual (%)</label>
                                <input type="number" id="calc80-input" value="35" min="0" max="100" step="1" inputmode="decimal" class="input-modern w-full p-4 text-xl font-bold">
                            </div>
                            <div>
                                <label for="calc80-pwr" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Potencia (kW)</label>
                                <input type="number" id="calc80-pwr" value="4.4" min="0.1" max="400" step="0.1" inputmode="decimal" class="input-modern w-full p-4 text-xl font-bold">
                            </div>
                            <div class="p-4 bg-indigo-50 dark:bg-indigo-900/20 rounded-2xl text-center border border-indigo-100 dark:border-indigo-800">
                                <p class="text-[11px] font-bold text-indigo-700 dark:text-indigo-300 uppercase mb-1">Poner el temporizador a</p>
                                <p class="text-3xl font-black text-indigo-700 dark:text-indigo-300" id="calc80-res">0 h 0 min</p>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- ==================== RECARGAS ==================== -->
            <section id="view-logs" role="tabpanel" aria-labelledby="tab-logs" tabindex="0" hidden class="space-y-6 animate-fade-in">
                <h2 class="sr-only">Registro de recargas</h2>

                <div class="bg-white dark:bg-slate-900 p-6 sm:p-8 rounded-3xl border border-slate-200 dark:border-slate-800">
                    <div class="flex flex-wrap justify-between items-center gap-3 mb-6">
                        <h3 class="font-bold" id="form-title">Registrar recarga</h3>
                        <div class="flex items-center gap-2">
                            <input type="checkbox" id="legacy-mode" class="w-4 h-4 text-indigo-600 rounded">
                            <label for="legacy-mode" class="text-xs font-bold text-slate-600 dark:text-slate-400 uppercase cursor-pointer hover:text-indigo-600">Carga histórica anual</label>
                        </div>
                    </div>

                    <form id="form-log" class="space-y-6" novalidate>
                        <div id="standard-fields" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                            <div>
                                <label for="log-date" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1 block">Fecha y hora</label>
                                <input type="datetime-local" id="log-date" class="input-modern w-full p-2.5 text-sm" required>
                                <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="log-date" role="alert"></p>
                            </div>
                            <div>
                                <label for="log-loc" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1 block">Ubicación</label>
                                <select id="log-loc" class="input-modern w-full p-2.5 text-sm">
                                    <option value="home">Casa</option>
                                    <option value="street">Pública</option>
                                </select>
                                <p class="min-h-[1rem]"></p>
                            </div>
                            <div class="public-only" hidden>
                                <label for="log-brand" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1 block">Operador</label>
                                <select id="log-brand" class="input-modern w-full p-2.5 text-sm font-bold">
                                    <option value="">Selecciona…</option>
                                    <optgroup label="España">
                                        <option value="Iberdrola">Iberdrola</option>
                                        <option value="Endesa X Way">Endesa X Way</option>
                                        <option value="Repsol">Repsol</option>
                                        <option value="Tesla">Tesla Superchargers</option>
                                        <option value="Zunder">Zunder</option>
                                        <option value="Wenea">Wenea</option>
                                        <option value="EDP">EDP</option>
                                        <option value="Ionity">Ionity</option>
                                        <option value="Powerdot">Powerdot</option>
                                        <option value="Moeve">Moeve (Cepsa)</option>
                                        <option value="Eranovum">Eranovum</option>
                                        <option value="Acciona">Acciona</option>
                                        <option value="BP Pulse">BP Pulse</option>
                                    </optgroup>
                                    <optgroup label="Andorra">
                                        <option value="FEDA">FEDA</option>
                                        <option value="Nord Andorrà">Nord Andorrà</option>
                                        <option value="Mútua Elèctrica">Mútua Elèctrica</option>
                                        <option value="Sercensa">Sercensa</option>
                                        <option value="Saba">Saba</option>
                                        <option value="Comú d'Ordino">Comú d'Ordino</option>
                                    </optgroup>
                                    <optgroup label="Francia">
                                        <option value="TotalEnergies">TotalEnergies</option>
                                        <option value="IZIVIA">IZIVIA</option>
                                        <option value="Electra">Electra</option>
                                        <option value="Fastned">Fastned</option>
                                        <option value="Carrefour/Lidl">Carrefour / Lidl</option>
                                        <option value="NW IECharge">NW IECharge</option>
                                        <option value="ENGIE Vianeo">ENGIE Vianeo</option>
                                        <option value="Freshmile">Freshmile</option>
                                        <option value="Allego">Allego</option>
                                        <option value="Driveco">Driveco</option>
                                        <option value="Bouygues">Bouygues</option>
                                    </optgroup>
                                </select>
                                <p class="min-h-[1rem]"></p>
                            </div>

                            <div>
                                <label for="log-kwh" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1 block">Energía (kWh)</label>
                                <input type="number" id="log-kwh" step="0.01" min="0" max="500" inputmode="decimal" class="input-modern w-full p-2.5 text-sm">
                                <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="log-kwh" role="alert"></p>
                            </div>
                            <div class="relative">
                                <label for="log-cost" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1 block">Coste total (€)</label>
                                <input type="number" id="log-cost" step="0.01" min="0" max="10000" inputmode="decimal" class="input-modern w-full p-2.5 text-sm font-bold">
                                <span id="auto-cost-badge" hidden class="absolute top-0 right-0 bg-emerald-100 text-emerald-800 text-[10px] font-black px-1.5 rounded-full uppercase">Auto</span>
                                <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="log-cost" role="alert"></p>
                            </div>
                            <div>
                                <label for="log-price-kwh" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1 block">Precio por kWh (€)</label>
                                <input type="number" id="log-price-kwh" step="0.001" min="0" max="10" inputmode="decimal" class="input-modern w-full p-2.5 text-sm" placeholder="Cálculo automático">
                                <p class="min-h-[1rem]"></p>
                            </div>

                            <div>
                                <label for="log-km" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1 block">Kilómetros parciales</label>
                                <input type="number" id="log-km" step="0.1" min="0" max="5000" inputmode="decimal" class="input-modern w-full p-2.5 text-sm">
                                <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="log-km" role="alert"></p>
                            </div>
                            <div class="public-only" hidden>
                                <label for="log-sub-cost" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1 block">Coste fijo o cuota (€)</label>
                                <input type="number" id="log-sub-cost" step="0.01" min="0" max="1000" inputmode="decimal" class="input-modern w-full p-2.5 text-sm" placeholder="Opcional">
                                <p class="min-h-[1rem]"></p>
                            </div>
                        </div>

                        <div id="advanced-toggle-container" class="border-t border-slate-200 dark:border-slate-800 pt-4">
                            <button type="button" id="btn-advanced" data-action="toggle-advanced" aria-expanded="false" aria-controls="advanced-fields"
                                    class="flex items-center gap-2 text-xs font-bold text-indigo-700 dark:text-indigo-300 hover:text-indigo-800">
                                <i id="adv-icon" class="fa-solid fa-chevron-right transition-transform" aria-hidden="true"></i> Datos avanzados (opcional)
                            </button>
                        </div>

                        <div id="advanced-fields" hidden class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 bg-slate-50 dark:bg-slate-800/30 p-4 rounded-xl">
                            <div>
                                <label for="log-soc-start" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1 block">Batería al inicio (%)</label>
                                <input type="number" id="log-soc-start" min="0" max="100" step="1" inputmode="decimal" class="input-modern w-full p-2 text-sm">
                                <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="log-soc-start" role="alert"></p>
                            </div>
                            <div>
                                <label for="log-soc-end" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1 block">Batería al final (%)</label>
                                <input type="number" id="log-soc-end" min="0" max="100" step="1" inputmode="decimal" class="input-modern w-full p-2 text-sm">
                                <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="log-soc-end" role="alert"></p>
                            </div>
                            <div>
                                <label for="log-odo-total" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1 block">Odómetro (km totales)</label>
                                <input type="number" id="log-odo-total" min="0" max="2000000" step="1" inputmode="decimal" class="input-modern w-full p-2 text-sm">
                                <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="log-odo-total" role="alert"></p>
                            </div>
                            <div>
                                <label for="log-power" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1 block">Potencia (kW)</label>
                                <input type="number" id="log-power" step="0.1" min="0" max="400" inputmode="decimal" class="input-modern w-full p-2 text-sm">
                                <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="log-power" role="alert"></p>
                            </div>
                            <div>
                                <label for="log-duration" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1 block">Duración (min)</label>
                                <input type="number" id="log-duration" min="0" max="10080" step="1" inputmode="decimal" class="input-modern w-full p-2 text-sm">
                                <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="log-duration" role="alert"></p>
                            </div>
                            <div class="public-only" hidden>
                                <label for="log-temp" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase mb-1 block">Temperatura exterior (°C)</label>
                                <input type="number" id="log-temp" min="-40" max="60" step="1" inputmode="decimal" class="input-modern w-full p-2 text-sm">
                                <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="log-temp" role="alert"></p>
                            </div>
                            <div class="flex items-center h-full pt-4">
                                <label class="flex items-center gap-2 cursor-pointer" for="log-precond">
                                    <input type="checkbox" id="log-precond" class="w-4 h-4 text-indigo-600 rounded border-slate-400">
                                    <span class="text-xs font-medium text-slate-700 dark:text-slate-300">Preacondicionamiento</span>
                                </label>
                            </div>
                        </div>

                        <div id="legacy-fields" hidden class="grid grid-cols-1 md:grid-cols-2 gap-4 bg-amber-50 dark:bg-amber-900/10 p-4 rounded-xl border border-amber-200 dark:border-amber-800/40">
                            <div class="md:col-span-2">
                                <label for="log-date-legacy" class="text-[11px] font-bold text-indigo-700 dark:text-indigo-300 uppercase">Fecha de la recarga</label>
                                <input type="datetime-local" id="log-date-legacy" class="input-modern w-full p-2 text-sm">
                                <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="log-date-legacy" role="alert"></p>
                            </div>
                            <div>
                                <label for="log-cost-legacy" class="text-[11px] font-bold text-indigo-700 dark:text-indigo-300 uppercase">Coste de la recarga (€)</label>
                                <input type="number" id="log-cost-legacy" step="0.01" min="0" max="100000" inputmode="decimal" class="input-modern w-full p-2 text-sm">
                                <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="log-cost-legacy" role="alert"></p>
                            </div>
                            <div>
                                <label for="log-km-legacy" class="text-[11px] font-bold text-indigo-700 dark:text-indigo-300 uppercase">Kilómetros parciales</label>
                                <input type="number" id="log-km-legacy" step="0.1" min="0" max="500000" inputmode="decimal" class="input-modern w-full p-2 text-sm">
                                <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="log-km-legacy" role="alert"></p>
                            </div>
                            <div>
                                <label for="log-ice-price" class="text-[11px] font-bold text-indigo-700 dark:text-indigo-300 uppercase">Precio del litro (€/L)</label>
                                <input type="number" id="log-ice-price" step="0.001" min="0" max="10" inputmode="decimal" class="input-modern w-full p-2 text-sm">
                                <p class="min-h-[1rem]"></p>
                            </div>
                            <div>
                                <label for="log-ice-cost" class="text-[11px] font-bold text-indigo-700 dark:text-indigo-300 uppercase">Coste del repostaje equivalente (€)</label>
                                <input type="number" id="log-ice-cost" step="0.01" min="0" max="100000" inputmode="decimal" class="input-modern w-full p-2 text-sm font-bold bg-white dark:bg-slate-900">
                                <p class="min-h-[1rem]"></p>
                            </div>
                        </div>

                        <p id="form-log-summary" class="text-sm font-bold text-red-600 dark:text-red-400 min-h-[1.25rem]" role="alert"></p>

                        <div class="flex justify-end gap-3 pt-2">
                            <button type="button" id="btn-cancel" data-action="cancel-log" hidden class="text-slate-600 dark:text-slate-300 hover:text-slate-900 font-bold px-4 py-2 text-sm">Cancelar</button>
                            <button type="submit" id="btn-submit" class="bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded-xl py-3 px-8 shadow-lg shadow-indigo-500/20 text-sm">Guardar recarga</button>
                        </div>
                    </form>
                </div>

                <div class="bg-white dark:bg-slate-900 rounded-3xl border border-slate-200 dark:border-slate-800 overflow-x-auto">
                    <table class="w-full text-left text-sm min-w-[44rem]">
                        <caption class="sr-only">Listado de recargas registradas, de la más reciente a la más antigua</caption>
                        <thead class="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-800 text-[11px] font-bold uppercase text-slate-600 dark:text-slate-400">
                            <tr>
                                <th scope="col" class="px-4 py-4">Fecha</th>
                                <th scope="col" class="px-4 py-4">Energía</th>
                                <th scope="col" class="px-4 py-4">Distancia</th>
                                <th scope="col" class="px-4 py-4 hidden sm:table-cell">Batería</th>
                                <th scope="col" class="px-4 py-4">Coste</th>
                                <th scope="col" class="px-4 py-4 text-center">Acciones</th>
                            </tr>
                        </thead>
                        <tbody id="logs-table"></tbody>
                    </table>
                </div>
            </section>

            <!-- ==================== BATERÍA OBD ==================== -->
            <section id="view-health" role="tabpanel" aria-labelledby="tab-health" tabindex="0" hidden class="space-y-6 animate-fade-in">
                <h2 class="sr-only">Salud de la batería</h2>

                <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <div class="lg:col-span-2 bg-white dark:bg-slate-900 p-6 rounded-3xl border border-slate-200 dark:border-slate-800 h-80">
                        <canvas id="chart-projection" role="img" aria-label="Evolución del estado de salud de la batería"></canvas>
                    </div>
                    <div class="bg-slate-900 text-white p-6 rounded-3xl shadow-xl flex flex-col justify-center text-center">
                        <p class="text-xs font-bold text-slate-300 uppercase mb-2" id="lbl-projection">Límite de garantía (70 %) estimado en</p>
                        <p class="text-2xl font-black text-emerald-400" id="projection-date" aria-labelledby="lbl-projection">Faltan datos</p>
                        <p class="text-[11px] text-slate-400 mt-4 uppercase tracking-wider">Tendencia basada en las lecturas OBD</p>
                    </div>
                </div>

                <div class="bg-white dark:bg-slate-900 p-6 sm:p-8 rounded-3xl border border-slate-200 dark:border-slate-800">
                    <h3 class="font-bold mb-6" id="obd-form-title">Nuevo registro técnico (OBD)</h3>
                    <form id="form-obd" class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 items-start" novalidate>
                        <div>
                            <label for="obd-date" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Fecha</label>
                            <input type="date" id="obd-date" class="input-modern w-full p-2 text-sm" required>
                            <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="obd-date" role="alert"></p>
                        </div>
                        <div>
                            <label for="obd-soh" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">SoH (%)</label>
                            <input type="number" id="obd-soh" step="0.1" min="0" max="100" inputmode="decimal" class="input-modern w-full p-2 text-sm" required aria-describedby="obd-fb-soh">
                            <p id="obd-fb-soh" class="text-[11px] mt-1 font-bold min-h-[1rem]"></p>
                            <p class="text-[11px] font-bold text-red-600 dark:text-red-400 min-h-[1rem]" data-error-for="obd-soh" role="alert"></p>
                        </div>
                        <div>
                            <label for="obd-odo" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Odómetro (km)</label>
                            <input type="number" id="obd-odo" min="0" max="2000000" step="1" inputmode="decimal" class="input-modern w-full p-2 text-sm">
                            <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="obd-odo" role="alert"></p>
                        </div>
                        <div>
                            <label for="obd-cap" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Capacidad (kWh)</label>
                            <input type="number" id="obd-cap" step="0.1" min="0" max="500" inputmode="decimal" class="input-modern w-full p-2 text-sm" aria-describedby="obd-fb-cap">
                            <p id="obd-fb-cap" class="text-[11px] mt-1 font-bold min-h-[1rem]"></p>
                            <p class="text-[11px] font-bold text-red-600 dark:text-red-400 min-h-[1rem]" data-error-for="obd-cap" role="alert"></p>
                        </div>
                        <div>
                            <label for="obd-mv" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Desbalanceo (mV)</label>
                            <input type="number" id="obd-mv" min="0" max="5000" step="1" inputmode="decimal" class="input-modern w-full p-2 text-sm" aria-describedby="obd-fb-mv">
                            <p id="obd-fb-mv" class="text-[11px] mt-1 font-bold min-h-[1rem]"></p>
                            <p class="text-[11px] font-bold text-red-600 dark:text-red-400 min-h-[1rem]" data-error-for="obd-mv" role="alert"></p>
                        </div>
                        <div>
                            <label for="obd-cycles" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Ciclos</label>
                            <input type="number" id="obd-cycles" min="0" max="100000" step="1" inputmode="decimal" class="input-modern w-full p-2 text-sm">
                            <p class="text-[11px] font-bold text-red-600 dark:text-red-400 mt-1 min-h-[1rem]" data-error-for="obd-cycles" role="alert"></p>
                        </div>

                        <div class="col-span-full">
                            <p id="form-obd-summary" class="text-sm font-bold text-red-600 dark:text-red-400 min-h-[1.25rem]" role="alert"></p>
                            <div class="flex gap-2 items-center justify-end">
                                <button type="button" id="btn-cancel-obd" data-action="cancel-obd" hidden class="text-slate-600 dark:text-slate-300 hover:text-slate-900 font-bold px-3 py-2 text-xs">Cancelar</button>
                                <button type="submit" id="btn-submit-obd" class="bg-slate-900 dark:bg-white text-white dark:text-slate-900 py-2 px-4 rounded-xl font-bold text-sm shadow-lg">Guardar</button>
                            </div>
                        </div>
                    </form>
                </div>

                <div class="bg-white dark:bg-slate-900 rounded-3xl border border-slate-200 dark:border-slate-800 overflow-x-auto">
                    <table class="w-full text-left text-sm min-w-[36rem]">
                        <caption class="sr-only">Lecturas OBD registradas, de la más reciente a la más antigua</caption>
                        <thead class="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-800 text-[11px] font-bold uppercase text-slate-600 dark:text-slate-400">
                            <tr>
                                <th scope="col" class="px-6 py-4">Fecha</th>
                                <th scope="col" class="px-6 py-4">SoH</th>
                                <th scope="col" class="px-6 py-4">Odómetro</th>
                                <th scope="col" class="px-6 py-4">Capacidad</th>
                                <th scope="col" class="px-6 py-4 text-center">Acciones</th>
                            </tr>
                        </thead>
                        <tbody id="obd-table"></tbody>
                    </table>
                </div>
            </section>

            <!-- ==================== CONFIGURACIÓN ==================== -->
            <section id="view-config" role="tabpanel" aria-labelledby="tab-config" tabindex="0" hidden class="grid grid-cols-1 md:grid-cols-2 gap-6 animate-fade-in">
                <h2 class="sr-only">Configuración</h2>

                <div class="bg-white dark:bg-slate-900 p-6 sm:p-8 rounded-3xl border border-slate-200 dark:border-slate-800">
                    <h3 class="font-bold mb-6 text-indigo-700 dark:text-indigo-300">Finanzas del vehículo</h3>
                    <div class="space-y-4">
                        <div>
                            <label for="conf-p-ev" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Precio de compra del eléctrico (€)</label>
                            <input type="number" id="conf-p-ev" min="0" max="1000000" step="1" inputmode="decimal" class="input-modern w-full p-3 text-sm" data-config>
                        </div>
                        <div>
                            <label for="conf-p-ice" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Precio de compra del de referencia (€)</label>
                            <input type="number" id="conf-p-ice" min="0" max="1000000" step="1" inputmode="decimal" class="input-modern w-full p-3 text-sm" data-config>
                        </div>
                        <div class="bg-indigo-50 dark:bg-indigo-900/20 p-3 rounded-xl border border-indigo-200 dark:border-indigo-800 flex flex-wrap gap-2 justify-between items-center">
                            <span class="text-xs font-bold text-indigo-700 dark:text-indigo-300 uppercase" id="lbl-target">Objetivo a amortizar</span>
                            <span class="text-lg font-black text-indigo-700 dark:text-indigo-300" id="conf-target-val" aria-labelledby="lbl-target">10.000 €</span>
                        </div>
                        <div class="pt-4 border-t border-slate-200 dark:border-slate-800">
                            <label for="conf-eff" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase block mb-2">Factor de realismo (%)</label>
                            <input type="range" id="conf-eff" min="50" max="100" step="1" class="w-full h-2 bg-slate-200 dark:bg-slate-700 rounded-lg appearance-none cursor-pointer" data-config>
                            <div class="flex justify-between text-[11px] font-bold text-slate-600 dark:text-slate-400 mt-1">
                                <span>50 %</span><span class="text-indigo-700 dark:text-indigo-300" id="eff-val-label">80 %</span><span>100 %</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="bg-white dark:bg-slate-900 p-6 sm:p-8 rounded-3xl border border-slate-200 dark:border-slate-800">
                    <div class="flex flex-wrap justify-between items-center gap-3 mb-6">
                        <h3 class="font-bold text-emerald-700 dark:text-emerald-400">Parámetros operativos</h3>
                        <button type="button" data-action="preset-iberdrola"
                                class="text-[11px] font-bold bg-indigo-50 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300 px-3 py-1.5 rounded-lg border border-indigo-200 dark:border-indigo-800 hover:bg-indigo-100 dark:hover:bg-indigo-900/50">
                            <i class="fa-solid fa-rotate-left mr-1" aria-hidden="true"></i> Cargar preset Iberdrola
                        </button>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
                        <div>
                            <label for="conf-t-day" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Luz punta (€/kWh)</label>
                            <input type="number" id="conf-t-day" step="0.001" min="0" max="10" inputmode="decimal" class="input-modern w-full p-3 text-sm" data-config>
                        </div>
                        <div>
                            <label for="conf-t-night" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Luz valle (€/kWh)</label>
                            <input type="number" id="conf-t-night" step="0.001" min="0" max="10" inputmode="decimal" class="input-modern w-full p-3 text-sm" data-config>
                        </div>
                    </div>
                    <div class="mb-4">
                        <label for="conf-p-home" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Potencia del cargador de casa (kW)</label>
                        <input type="number" id="conf-p-home" step="0.1" min="0.1" max="400" inputmode="decimal" class="input-modern w-full p-3 text-sm" data-config>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label for="conf-ice-l" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Consumo de referencia (L/100 km)</label>
                            <input type="number" id="conf-ice-l" step="0.1" min="0" max="60" inputmode="decimal" class="input-modern w-full p-3 text-sm" data-config>
                        </div>
                        <div>
                            <label for="conf-ice-p" class="text-[11px] font-bold text-slate-600 dark:text-slate-400 uppercase">Precio del litro (€/L)</label>
                            <input type="number" id="conf-ice-p" step="0.01" min="0" max="10" inputmode="decimal" class="input-modern w-full p-3 text-sm" data-config>
                        </div>
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-6">
                        <button type="button" data-action="export"
                                class="text-xs border border-slate-300 dark:border-slate-700 p-3 rounded-xl font-bold bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200">
                            <i class="fa-solid fa-file-shield mr-1" aria-hidden="true"></i> Copia de seguridad (cifrada)
                        </button>
                        <div>
                            <label for="import-file" class="block w-full text-center text-xs border border-dashed border-slate-400 dark:border-slate-600 p-3 rounded-xl font-bold cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-800 dark:text-slate-200">
                                <i class="fa-solid fa-file-import mr-1" aria-hidden="true"></i> Importar JSON
                            </label>
                            <input type="file" id="import-file" accept="application/json,.json" class="sr-only">
                        </div>
                    </div>

                    <p class="text-[11px] text-slate-600 dark:text-slate-400 mt-4">
                        <i class="fa-solid fa-circle-info mr-1" aria-hidden="true"></i>
                        Los datos se guardan en este navegador sin cifrar para poder trabajar sin conexión.
                        Usa siempre contraseña al exportar y no uses un equipo compartido.
                    </p>
                </div>
            </section>
        </div>
    </main>

<script>
'use strict';
(() => {

// ============================================================================
//  1. LOCALIZACIÓN (es-ES)
// ============================================================================
const LOCALE = 'es-ES';

const fmtEur      = new Intl.NumberFormat(LOCALE, { style: 'currency', currency: 'EUR' });
const fmtEur3     = new Intl.NumberFormat(LOCALE, { style: 'currency', currency: 'EUR', minimumFractionDigits: 3, maximumFractionDigits: 3 });
const fmtEnteroEur= new Intl.NumberFormat(LOCALE, { style: 'currency', currency: 'EUR', maximumFractionDigits: 0 });
const fmtFecha    = new Intl.DateTimeFormat(LOCALE, { day: '2-digit', month: '2-digit', year: 'numeric' });
const fmtFechaCorta = new Intl.DateTimeFormat(LOCALE, { day: '2-digit', month: '2-digit' });
const fmtMesAnio  = new Intl.DateTimeFormat(LOCALE, { month: 'long', year: 'numeric' });
const fmtMesAnioCorto = new Intl.DateTimeFormat(LOCALE, { month: 'short', year: 'numeric' });

const num = (v, dec = 0) => new Intl.NumberFormat(LOCALE, { minimumFractionDigits: dec, maximumFractionDigits: dec }).format(Number.isFinite(v) ? v : 0);
const eur = (v, dec = 2) => (dec === 3 ? fmtEur3 : dec === 0 ? fmtEnteroEur : fmtEur).format(Number.isFinite(v) ? v : 0);
const pct = (v, dec = 1) => num(Number.isFinite(v) ? v : 0, dec) + ' %';
const fecha = (v) => { const d = new Date(v); return Number.isNaN(d.getTime()) ? '—' : fmtFecha.format(d); };
/** Duración en formato español de 24 h: "2 h 5 min". */
const duracion = (minutos) => {
    if (!Number.isFinite(minutos) || minutos < 0) return '0 h 0 min';
    const m = Math.round(minutos);
    return `${Math.floor(m / 60)} h ${m % 60} min`;
};

// ============================================================================
//  2. ADAPTADOR DE FECHAS PARA CHART.JS (es-ES, semana de lunes a domingo)
//     Sustituye a chartjs-adapter-date-fns: una dependencia externa menos y,
//     sobre todo, elimina el domingo como primer día de la semana y los meses
//     en inglés que traía el adaptador por defecto.
// ============================================================================
if (window.Chart) {
    const FORMATOS = {
        datetime: 'dd/MM/yyyy HH:mm', millisecond: 'HH:mm:ss', second: 'HH:mm:ss',
        minute: 'HH:mm', hour: 'HH:mm', day: 'dd/MM', week: 'dd/MM',
        month: 'MMM yyyy', quarter: 'MMM yyyy', year: 'yyyy'
    };
    const INTL = {
        'dd/MM/yyyy HH:mm': new Intl.DateTimeFormat(LOCALE, { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }),
        'HH:mm:ss': new Intl.DateTimeFormat(LOCALE, { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }),
        'HH:mm': new Intl.DateTimeFormat(LOCALE, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }),
        'dd/MM': fmtFechaCorta,
        'MMM yyyy': fmtMesAnioCorto,
        'yyyy': new Intl.DateTimeFormat(LOCALE, { year: 'numeric' })
    };
    const MS = { millisecond: 1, second: 1000, minute: 60000, hour: 3600000, day: 86400000, week: 604800000 };

    const inicioDe = (ts, unidad) => {
        const d = new Date(ts);
        switch (unidad) {
            case 'second':  d.setMilliseconds(0); break;
            case 'minute':  d.setSeconds(0, 0); break;
            case 'hour':    d.setMinutes(0, 0, 0); break;
            case 'day':     d.setHours(0, 0, 0, 0); break;
            case 'week':
            case 'isoWeek': d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - ((d.getDay() + 6) % 7)); break; // lunes
            case 'month':   d.setDate(1); d.setHours(0, 0, 0, 0); break;
            case 'quarter': d.setMonth(Math.floor(d.getMonth() / 3) * 3, 1); d.setHours(0, 0, 0, 0); break;
            case 'year':    d.setMonth(0, 1); d.setHours(0, 0, 0, 0); break;
            default: return ts;
        }
        return d.getTime();
    };
    const sumar = (ts, cantidad, unidad) => {
        const d = new Date(ts);
        const n = Math.round(cantidad);
        switch (unidad) {
            case 'week':    d.setDate(d.getDate() + n * 7); return d.getTime();
            case 'day':     d.setDate(d.getDate() + n); return d.getTime();
            case 'month':   d.setMonth(d.getMonth() + n); return d.getTime();
            case 'quarter': d.setMonth(d.getMonth() + n * 3); return d.getTime();
            case 'year':    d.setFullYear(d.getFullYear() + n); return d.getTime();
            default:        return ts + n * (MS[unidad] || 1);
        }
    };
    const mesesEntre = (a, b) => (new Date(a).getFullYear() - new Date(b).getFullYear()) * 12 + (new Date(a).getMonth() - new Date(b).getMonth());

    Chart._adapters._date.override({
        formats: () => FORMATOS,
        parse: (valor) => {
            if (valor === null || valor === undefined) return null;
            if (valor instanceof Date) { const t = valor.getTime(); return Number.isNaN(t) ? null : t; }
            if (typeof valor === 'number') return Number.isFinite(valor) ? valor : null;
            const t = new Date(valor).getTime();
            return Number.isNaN(t) ? null : t;
        },
        format: (ts, formato) => (INTL[formato] || INTL['dd/MM']).format(new Date(ts)),
        add: sumar,
        diff: (max, min, unidad) => {
            switch (unidad) {
                case 'month':   return mesesEntre(max, min);
                case 'quarter': return mesesEntre(max, min) / 3;
                case 'year':    return mesesEntre(max, min) / 12;
                default:        return (max - min) / (MS[unidad] || 1);
            }
        },
        startOf: inicioDe,
        endOf: (ts, unidad) => sumar(inicioDe(ts, unidad), 1, unidad) - 1
    });
}

// ============================================================================
//  3. UTILIDADES
// ============================================================================
const $ = (id) => document.getElementById(id);

/** Escapa texto antes de insertarlo en HTML. Única barrera contra XSS almacenado:
 *  `brand` y compañía pueden venir de un JSON importado o del bot de Telegram. */
const esc = (v) => String(v ?? '').replace(/[&<>"'`]/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;'
})[c]);

const clamp = (v, min, max) => Math.min(Math.max(v, min), max);

/** Lee un input numérico. Acepta coma decimal (teclado español). null si está vacío. */
function leerNum(id) {
    const el = $(id);
    if (!el) return null;
    const bruto = String(el.value).trim().replace(',', '.');
    if (bruto === '') return null;
    const v = Number.parseFloat(bruto);
    return Number.isFinite(v) ? v : null;
}
/** Igual que leerNum pero devuelve 0 cuando no hay valor (para campos obligatorios). */
const leerNum0 = (id) => leerNum(id) ?? 0;

/** Fecha/hora local en el formato que exigen los input datetime-local / date. */
function ahoraLocalISO(soloFecha = false) {
    const n = new Date();
    n.setMinutes(n.getMinutes() - n.getTimezoneOffset());
    return n.toISOString().slice(0, soloFecha ? 10 : 16);
}

function anunciar(texto) { const lr = $('live-region'); if (lr) lr.textContent = texto; }

let temporizadorToast = null;
function mostrarToast(mensaje = 'Guardado local', icono = 'fa-solid fa-floppy-disk text-emerald-400') {
    const t = $('save-toast');
    if (!t) return;
    $('toast-msg').textContent = mensaje;
    $('toast-icon').className = icono;
    t.classList.remove('translate-y-24');
    anunciar(mensaje);
    clearTimeout(temporizadorToast);
    temporizadorToast = setTimeout(() => t.classList.add('translate-y-24'), 2500);
}

// ============================================================================
//  4. ESTADO Y SANEAMIENTO DE DATOS
// ============================================================================
const AJUSTES_POR_DEFECTO = {
    model: 'Opel Mokka-e', capacity: 46, wltp: 332, efficiency: 80,
    priceEV: 32000, priceICE: 22000,
    iceModel: 'Opel Mokka 1.2 Turbo 130', iceFuel: 'gasolina95', iceLiters: 6.2,
    icePrice: 1.50, icePriceAuto: true,
    pDay: 0.22, pNight: 0.03, homePower: 4.4
};
const LIMITE_TEXTO = 60;
const MAX_BYTES_IMPORT = 8 * 1024 * 1024; // 8 MB

// Acepta también coma decimal: un JSON escrito a mano o generado por EVBot.py
// podría traer "9,5" y parseFloat lo truncaría a 9 en silencio.
const numSeguro = (v, def = 0) => {
    const n = Number.parseFloat(typeof v === 'string' ? v.replace(/\s/g, '').replace(',', '.') : v);
    return Number.isFinite(n) ? n : def;
};
const textoSeguro = (v) => (typeof v === 'string' ? v.slice(0, LIMITE_TEXTO) : '');

/**
 * Normaliza cualquier objeto de datos (localStorage, archivo importado o NAS).
 * Fuerza los tipos, descarta basura y conserva las claves extra que añade el
 * bot de Telegram para no romper la compatibilidad con EVBot.py.
 */
function normalizarDatos(bruto) {
    const base = { settings: { ...AJUSTES_POR_DEFECTO }, logs: [], obd: [] };
    if (!bruto || typeof bruto !== 'object') return base;

    if (bruto.settings && typeof bruto.settings === 'object') {
        for (const [k, v] of Object.entries(bruto.settings)) {
            if (k in AJUSTES_POR_DEFECTO) {
                base.settings[k] = typeof AJUSTES_POR_DEFECTO[k] === 'number' ? numSeguro(v, AJUSTES_POR_DEFECTO[k])
                                 : typeof AJUSTES_POR_DEFECTO[k] === 'boolean' ? Boolean(v)
                                 : textoSeguro(v) || AJUSTES_POR_DEFECTO[k];
            } else if (['string', 'number', 'boolean'].includes(typeof v)) {
                base.settings[k] = typeof v === 'string' ? textoSeguro(v) : v; // claves del bot
            }
        }
    }

    let semilla = Date.now();
    const idUnico = () => `${semilla++}`;

    if (Array.isArray(bruto.logs)) {
        base.logs = bruto.logs.filter((l) => l && typeof l === 'object').map((l) => {
            const reg = {
                id: (typeof l.id === 'number' || typeof l.id === 'string') && String(l.id).length <= 32 ? String(l.id) : idUnico(),
                date: textoSeguro(l.date),
                km: clamp(numSeguro(l.km), 0, 1e6),
                cost: clamp(numSeguro(l.cost), 0, 1e6),
                type: ['home', 'street', 'legacy'].includes(l.type) ? l.type : 'home'
            };
            if (l.kwh !== undefined) reg.kwh = clamp(numSeguro(l.kwh), 0, 1e5);
            if (l.iceCost !== undefined && l.iceCost !== null) reg.iceCost = clamp(numSeguro(l.iceCost), 0, 1e6);
            if (l.histIcePrice !== undefined) reg.histIcePrice = clamp(numSeguro(l.histIcePrice), 0, 100);
            if (Number.isFinite(numSeguro(l.socStart, NaN))) reg.socStart = clamp(numSeguro(l.socStart), 0, 100);
            if (Number.isFinite(numSeguro(l.socEnd, NaN)))   reg.socEnd   = clamp(numSeguro(l.socEnd), 0, 100);
            if (l.odo !== undefined)      reg.odo = clamp(numSeguro(l.odo), 0, 2e6);
            if (l.power !== undefined)    reg.power = clamp(numSeguro(l.power), 0, 1000);
            if (l.duration !== undefined) reg.duration = clamp(numSeguro(l.duration), 0, 1e5);
            if (l.temp !== undefined)     reg.temp = clamp(numSeguro(l.temp), -80, 80);
            if (l.subCost !== undefined && l.subCost !== null) reg.subCost = clamp(numSeguro(l.subCost), 0, 1e5);
            if (l.precond !== undefined)  reg.precond = Boolean(l.precond);
            if (l.brand !== undefined)    reg.brand = textoSeguro(l.brand);
            if (l.dateEnd !== undefined)  reg.dateEnd = textoSeguro(l.dateEnd);
            return reg;
        });
    }

    if (Array.isArray(bruto.obd)) {
        base.obd = bruto.obd.filter((o) => o && typeof o === 'object').map((o) => ({
            id: (typeof o.id === 'number' || typeof o.id === 'string') && String(o.id).length <= 32 ? String(o.id) : idUnico(),
            date: textoSeguro(o.date),
            soh: clamp(numSeguro(o.soh), 0, 100),
            odo: clamp(numSeguro(o.odo), 0, 2e6),
            cap: clamp(numSeguro(o.cap), 0, 500),
            mv: clamp(numSeguro(o.mv), 0, 10000),
            cycles: clamp(numSeguro(o.cycles), 0, 1e6)
        }));
    }
    return base;
}

function cargarDeLocalStorage() {
    try {
        const bruto = localStorage.getItem('evTrackerData');
        return normalizarDatos(bruto ? JSON.parse(bruto) : null);
    } catch (e) {
        console.warn('Datos locales ilegibles, se parte de la configuración por defecto.', e);
        return normalizarDatos(null);
    }
}

let appData = cargarDeLocalStorage();
const charts = {};
let modoGrafica = 'cumulative';
let contenidoPendiente = null;
let accionModal = null;
let editandoLogId = null;
let editandoObdId = null;
let idPendienteBorrado = null;
let tipoPendienteBorrado = null;
let claveSesion = null;          // contraseña en memoria, nunca se persiste
let backendDisponible = null;    // null = sin probar, false = no hay save.php
let ultimoFoco = null;

// ============================================================================
//  5. PERSISTENCIA
// ============================================================================
function guardarDatos() {
    const jsonPlano = JSON.stringify(appData);
    try {
        localStorage.setItem('evTrackerData', jsonPlano);
    } catch (e) {
        console.warn('No se ha podido escribir en el almacenamiento local.', e);
    }
    let carga = jsonPlano;
    if (claveSesion) {
        carga = JSON.stringify({ isEncrypted: true, content: CryptoJS.AES.encrypt(jsonPlano, claveSesion).toString() });
    }
    enviarAlServidor(carga);
}

async function enviarAlServidor(json) {
    if (location.protocol === 'file:' || backendDisponible === false) return;
    try {
        const res = await fetch('save.php', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: json });
        backendDisponible = res.ok;
        if (res.ok) {
            mostrarToast(claveSesion ? 'Guardado cifrado en el NAS' : 'Guardado en el NAS',
                         claveSesion ? 'fa-solid fa-lock text-emerald-400' : 'fa-solid fa-cloud-arrow-up text-emerald-400');
        }
    } catch (e) {
        backendDisponible = false;
        console.info('Sin backend save.php: solo se guarda en local.');
    }
}

// ============================================================================
//  6. TEMA Y NAVEGACIÓN
// ============================================================================
function aplicarTemaAGraficas() {
    if (!window.Chart) return;
    const oscuro = document.documentElement.classList.contains('dark');
    Chart.defaults.color = oscuro ? '#cbd5e1' : '#475569';
    Chart.defaults.borderColor = oscuro ? '#334155' : '#e2e8f0';
    Chart.defaults.locale = LOCALE;
}

function alternarTema() {
    const oscuro = document.documentElement.classList.toggle('dark');
    try { localStorage.setItem('theme', oscuro ? 'dark' : 'light'); } catch (e) { /* sin almacenamiento */ }
    aplicarTemaAGraficas();
    refrescarUI();
}

const PESTANAS = ['dashboard', 'calculator', 'logs', 'health', 'config'];

function cambiarPestana(nombre, moverFoco = false) {
    if (!PESTANAS.includes(nombre)) return;
    PESTANAS.forEach((p) => {
        const tab = $('tab-' + p);
        const panel = $('view-' + p);
        const activa = p === nombre;
        if (tab) { tab.setAttribute('aria-selected', String(activa)); tab.tabIndex = activa ? 0 : -1; }
        if (panel) panel.hidden = !activa;
    });
    if (moverFoco) $('tab-' + nombre)?.focus();

    if (nombre === 'calculator') actualizarCalculadoras();
    if (nombre === 'dashboard') actualizarPanel();
    if (nombre === 'logs') renderRecargas();
    if (nombre === 'health') { renderSalud(); renderTablaObd(); }
}

// ============================================================================
//  7. CONFIGURACIÓN
// ============================================================================
function cargarConfig() {
    const s = appData.settings;
    const poner = (id, v) => { const el = $(id); if (el) el.value = v; };
    poner('conf-p-ev', s.priceEV);   poner('conf-p-ice', s.priceICE);
    poner('conf-eff', s.efficiency); poner('conf-t-day', s.pDay);
    poner('conf-t-night', s.pNight); poner('conf-ice-l', s.iceLiters);
    poner('conf-ice-p', s.icePrice); poner('conf-p-home', s.homePower);

    if ($('eff-val-label')) $('eff-val-label').textContent = pct(s.efficiency, 0);
    if ($('calc-factor-wltp-label')) $('calc-factor-wltp-label').textContent = `Base (${pct(s.efficiency, 0)})`;
    if ($('conf-target-val')) $('conf-target-val').textContent = eur(s.priceEV - s.priceICE, 0);
}

function guardarConfig() {
    const s = appData.settings;
    s.priceEV   = clamp(leerNum0('conf-p-ev'), 0, 1e6);
    s.priceICE  = clamp(leerNum0('conf-p-ice'), 0, 1e6);
    s.efficiency= clamp(leerNum('conf-eff') ?? 80, 10, 100);
    s.pDay      = clamp(leerNum0('conf-t-day'), 0, 10);
    s.pNight    = clamp(leerNum0('conf-t-night'), 0, 10);
    s.iceLiters = clamp(leerNum0('conf-ice-l'), 0, 60);
    s.icePrice  = clamp(leerNum0('conf-ice-p'), 0, 10);
    s.homePower = clamp(leerNum('conf-p-home') ?? 4.4, 0.1, 400);
    guardarDatos();
    mostrarToast('Configuración guardada');
    cargarConfig();
    actualizarPanel();
    calcularEstimaciones('percent');
}

function aplicarPresetIberdrola() {
    if (!confirm('¿Cargar las tarifas de Iberdrola (0,22 €/kWh punta y 0,03 €/kWh valle)?')) return;
    appData.settings.pDay = 0.22;
    appData.settings.pNight = 0.03;
    guardarDatos();
    cargarConfig();
    mostrarToast('Tarifas actualizadas');
}

// ============================================================================
//  8. CÁLCULOS AGREGADOS
// ============================================================================
/** Coste equivalente del vehículo de referencia para una recarga concreta. */
function costeReferencia(l) {
    if (Number.isFinite(l.iceCost) && l.iceCost > 0) return l.iceCost;
    return (l.km / 100) * appData.settings.iceLiters * appData.settings.icePrice;
}

function agregarPorAnio() {
    const d = {};
    appData.logs.forEach((l) => {
        const t = new Date(l.date);
        if (Number.isNaN(t.getTime())) return;
        const y = t.getFullYear();
        d[y] ??= { ev: 0, ice: 0, km: 0, kwh: 0, home: 0, street: 0 };
        d[y].ev += l.cost;
        d[y].ice += costeReferencia(l);
        d[y].km += l.km;
        d[y].kwh += l.kwh || 0;
        if (l.type === 'street') d[y].street += l.kwh || 0; else d[y].home += l.kwh || 0;
    });
    return d;
}

function agregarPorMes() {
    const d = {};
    appData.logs.forEach((l) => {
        const t = new Date(l.date);
        if (Number.isNaN(t.getTime())) return;
        const clave = `${t.getFullYear()}-${String(t.getMonth() + 1).padStart(2, '0')}`;
        d[clave] ??= { cost: 0, km: 0 };
        d[clave].cost += l.cost;
        d[clave].km += l.km;
    });
    return d;
}

const etiquetaMes = (clave) => {
    const [a, m] = clave.split('-');
    return fmtMesAnioCorto.format(new Date(Number(a), Number(m) - 1, 1));
};

const sohActual = () => (appData.obd.length ? appData.obd[appData.obd.length - 1].soh : 100);

// ============================================================================
//  9. PANEL Y GRÁFICAS
// ============================================================================
function destruir(clave) { if (charts[clave]) { charts[clave].destroy(); delete charts[clave]; } }

const ejeEuros = { ticks: { callback: (v) => eur(v, 0) } };

function actualizarPanel() {
    let totalEv = 0, totalIce = 0;
    appData.logs.forEach((l) => { totalEv += l.cost; totalIce += costeReferencia(l); });

    const ahorro = totalIce - totalEv;
    const objetivo = appData.settings.priceEV - appData.settings.priceICE;
    const roi = objetivo > 0 ? clamp((ahorro / objetivo) * 100, 0, 100) : 100;
    const soh = sohActual();

    $('kpi-savings').textContent = eur(ahorro);
    $('kpi-roi').textContent = pct(roi);
    $('roi-bar').style.width = roi + '%';
    $('roi-progress').setAttribute('aria-valuenow', roi.toFixed(1));
    $('kpi-soh').textContent = pct(soh);
    $('kpi-range').textContent = num(Math.round(appData.settings.wltp * (soh / 100) * (appData.settings.efficiency / 100))) + ' km';
    $('kpi-range-desc').textContent = `Factor: ${pct(appData.settings.efficiency, 0)}`;

    renderGraficaPrincipal();
    renderGraficasAnuales();
    renderGraficasUbicacion();
    renderGraficasIngenieria();
    renderCoste100km();
    renderProyeccionRoi();
}

function renderGraficaPrincipal() {
    const el = $('chart-main'); if (!el || !window.Chart) return;
    destruir('main');
    const logs = [...appData.logs].filter((l) => !Number.isNaN(new Date(l.date).getTime()))
                                  .sort((a, b) => new Date(a.date) - new Date(b.date));

    if (modoGrafica === 'cumulative') {
        let acumulado = 0;
        const datos = logs.map((l) => { acumulado += costeReferencia(l) - l.cost; return { x: new Date(l.date).getTime(), y: acumulado }; });
        charts.main = new Chart(el, {
            type: 'line',
            data: { datasets: [{ label: 'Ahorro acumulado', data: datos, borderColor: '#4f46e5', tension: 0.35, fill: true, backgroundColor: 'rgba(79,70,229,.08)', pointRadius: 3 }] },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { tooltip: { callbacks: { label: (c) => `Ahorro: ${eur(c.parsed.y)}` } } },
                scales: { x: { type: 'time', time: { unit: 'month' }, grid: { display: false } }, y: { ...ejeEuros, border: { display: false } } }
            }
        });
    } else {
        const agg = agregarPorAnio();
        const anios = Object.keys(agg).sort();
        charts.main = new Chart(el, {
            type: 'bar',
            data: { labels: anios, datasets: [{ label: 'Ahorro neto', data: anios.map((y) => agg[y].ice - agg[y].ev), backgroundColor: '#4f46e5', borderRadius: 6 }] },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { tooltip: { callbacks: { label: (c) => `Ahorro: ${eur(c.parsed.y)}` } } },
                scales: { y: { ...ejeEuros, border: { display: false } }, x: { grid: { display: false } } }
            }
        });
    }
}

function renderGraficasAnuales() {
    if (!window.Chart) return;
    const agg = agregarPorAnio();
    const anios = Object.keys(agg).sort();

    const elCostes = $('chart-costs-annual');
    if (elCostes) {
        destruir('costesAnuales');
        charts.costesAnuales = new Chart(elCostes, {
            type: 'bar',
            data: { labels: anios, datasets: [
                { label: 'Eléctrico', data: anios.map((k) => agg[k].ev), backgroundColor: '#4f46e5' },
                { label: 'Referencia (gasolina)', data: anios.map((k) => agg[k].ice), backgroundColor: '#94a3b8' }
            ] },
            options: { responsive: true, maintainAspectRatio: false,
                plugins: { tooltip: { callbacks: { label: (c) => `${c.dataset.label}: ${eur(c.parsed.y)}` } } },
                scales: { x: { grid: { display: false } }, y: ejeEuros } }
        });
    }

    const elUso = $('chart-usage-annual');
    if (elUso) {
        destruir('usoAnual');
        charts.usoAnual = new Chart(elUso, {
            type: 'bar',
            data: { labels: anios, datasets: [
                { label: 'Kilómetros', data: anios.map((k) => agg[k].km), backgroundColor: '#059669', yAxisID: 'y' },
                { label: 'kWh', data: anios.map((k) => agg[k].kwh), backgroundColor: '#d97706', yAxisID: 'y1' }
            ] },
            options: { responsive: true, maintainAspectRatio: false,
                scales: { x: { grid: { display: false } }, y: { position: 'left' }, y1: { position: 'right', grid: { display: false } } } }
        });
    }
}

function renderGraficasUbicacion() {
    if (!window.Chart) return;
    const agg = agregarPorAnio();
    const anios = Object.keys(agg).sort();

    const elMix = $('chart-location-annual');
    if (elMix) {
        destruir('mix');
        charts.mix = new Chart(elMix, {
            type: 'bar',
            data: { labels: anios, datasets: [
                { label: 'Casa', data: anios.map((k) => agg[k].home), backgroundColor: '#4f46e5' },
                { label: 'Pública', data: anios.map((k) => agg[k].street), backgroundColor: '#059669' }
            ] },
            options: { responsive: true, maintainAspectRatio: false, scales: { x: { stacked: true, grid: { display: false } }, y: { stacked: true } } }
        });
    }

    const elMarcas = $('chart-brands');
    if (elMarcas) {
        destruir('marcas');
        const conteo = {};
        appData.logs.filter((l) => l.type === 'street').forEach((l) => {
            const marca = l.brand || 'Otros';
            conteo[marca] = (conteo[marca] || 0) + 1;
        });
        charts.marcas = new Chart(elMarcas, {
            type: 'doughnut',
            data: { labels: Object.keys(conteo), datasets: [{ data: Object.values(conteo), backgroundColor: ['#4f46e5', '#db2777', '#d97706', '#059669', '#2563eb', '#7c3aed', '#0891b2'] }] },
            options: { responsive: true, maintainAspectRatio: false, cutout: '70%', plugins: { legend: { position: 'right' } } }
        });
    }
}

function renderGraficasIngenieria() {
    if (!window.Chart) return;

    const elOp = $('chart-operator-price');
    if (elOp) {
        destruir('operadores');
        const datos = {};
        appData.logs.filter((l) => l.type === 'street' && l.brand && l.kwh > 0).forEach((l) => {
            datos[l.brand] ??= { cost: 0, kwh: 0 };
            datos[l.brand].cost += l.cost;
            datos[l.brand].kwh += l.kwh;
        });
        const marcas = Object.keys(datos).sort((a, b) => datos[a].cost / datos[a].kwh - datos[b].cost / datos[b].kwh);
        charts.operadores = new Chart(elOp, {
            type: 'bar',
            data: { labels: marcas, datasets: [{ label: 'Precio real (€/kWh)', data: marcas.map((m) => datos[m].cost / datos[m].kwh), backgroundColor: '#6366f1', borderRadius: 4 }] },
            options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false,
                plugins: { tooltip: { callbacks: { label: (c) => eur(c.parsed.x, 3) + '/kWh' } } },
                scales: { x: { grid: { display: false }, ticks: { callback: (v) => eur(v, 3) } } } }
        });
    }

    const elCiclos = $('chart-charging-health');
    if (elCiclos) {
        destruir('ciclos');
        const sesiones = appData.logs.filter((l) => Number.isFinite(l.socStart) && Number.isFinite(l.socEnd) && l.socEnd > 0).slice(-20);
        const zonaOptima = {
            id: 'zonaOptima',
            beforeDatasetsDraw(chart) {
                const { ctx, chartArea, scales } = chart;
                if (!chartArea || !scales.y) return;
                const y80 = scales.y.getPixelForValue(80), y20 = scales.y.getPixelForValue(20);
                if (!Number.isFinite(y80) || !Number.isFinite(y20)) return;
                ctx.save();
                ctx.fillStyle = 'rgba(5,150,105,.12)';
                ctx.fillRect(chartArea.left, y80, chartArea.right - chartArea.left, y20 - y80);
                ctx.restore();
            }
        };
        charts.ciclos = new Chart(elCiclos, {
            type: 'bar',
            data: { labels: sesiones.map((l) => fecha(l.date)), datasets: [{ label: 'Rango de carga (%)', data: sesiones.map((l) => [l.socStart, l.socEnd]), backgroundColor: '#4f46e5', borderRadius: 4, barPercentage: 0.5 }] },
            options: { responsive: true, maintainAspectRatio: false, scales: { y: { min: 0, max: 100, ticks: { callback: (v) => pct(v, 0) } } },
                plugins: { tooltip: { callbacks: { label: (c) => `Inicio ${pct(c.raw[0], 0)} → final ${pct(c.raw[1], 0)}` } } } },
            plugins: [zonaOptima]
        });
    }

    const elEf = $('chart-charging-efficiency');
    if (elEf) {
        destruir('eficiencia');
        const sesiones = appData.logs.filter((l) => l.power > 0 && l.duration > 0 && l.kwh > 0).slice(-20);
        charts.eficiencia = new Chart(elEf, {
            type: 'bar',
            data: { labels: sesiones.map((l) => fecha(l.date)), datasets: [
                { label: 'Potencia teórica (kW)', data: sesiones.map((l) => l.power), backgroundColor: '#94a3b8', borderRadius: 4, order: 2 },
                { label: 'Potencia real media (kW)', data: sesiones.map((l) => l.kwh / (l.duration / 60)), backgroundColor: '#059669', borderRadius: 4, order: 1 }
            ] },
            options: { responsive: true, maintainAspectRatio: false,
                plugins: { tooltip: { callbacks: { label: (c) => `${c.dataset.label}: ${num(c.parsed.y, 1)} kW` } } },
                scales: { x: { grid: { display: false } } } }
        });
    }
}

function renderCoste100km() {
    const el = $('chart-cost-100km'); if (!el || !window.Chart) return;
    destruir('coste100');
    const mensual = agregarPorMes();
    const claves = Object.keys(mensual).sort().filter((k) => mensual[k].km > 0); // evita división por cero
    const costeEv = claves.map((k) => (mensual[k].cost / mensual[k].km) * 100);
    const costeRef = appData.settings.iceLiters * appData.settings.icePrice;
    charts.coste100 = new Chart(el, {
        type: 'line',
        data: { labels: claves.map(etiquetaMes), datasets: [
            { label: 'Eléctrico real (€/100 km)', data: costeEv, borderColor: '#7c3aed', backgroundColor: 'rgba(124,58,237,.1)', fill: true, tension: 0.35 },
            { label: 'Referencia gasolina (€/100 km)', data: claves.map(() => costeRef), borderColor: '#dc2626', borderDash: [5, 5], pointRadius: 0, borderWidth: 2 }
        ] },
        options: { responsive: true, maintainAspectRatio: false,
            plugins: { tooltip: { callbacks: { label: (c) => `${c.dataset.label}: ${eur(c.parsed.y)}` } } },
            scales: { y: { beginAtZero: true, ...ejeEuros } } }
    });
}

function renderProyeccionRoi() {
    const el = $('chart-roi-projection'); if (!el || !window.Chart) return;
    destruir('proyeccionRoi');
    const texto = $('roi-prediction-text');

    let ahorro = 0;
    appData.logs.forEach((l) => { ahorro += costeReferencia(l) - l.cost; });
    const objetivo = appData.settings.priceEV - appData.settings.priceICE;

    if (objetivo <= 0 || ahorro <= 0 || appData.logs.length < 2) { texto.textContent = 'Faltan datos para proyectar'; return; }

    const ordenados = [...appData.logs].filter((l) => !Number.isNaN(new Date(l.date).getTime())).sort((a, b) => new Date(a.date) - new Date(b.date));
    if (ordenados.length < 2) { texto.textContent = 'Faltan datos para proyectar'; return; }

    const primera = new Date(ordenados[0].date);
    const ahora = new Date();
    const dias = (ahora - primera) / 86400000;
    if (dias < 30) { texto.textContent = 'Se necesitan al menos 30 días de datos'; return; }

    const ahorroDiario = ahorro / dias;
    if (ahorroDiario <= 0) { texto.textContent = 'Faltan datos para proyectar'; return; }

    const diasRestantes = Math.min((objetivo - ahorro) / ahorroDiario, 365 * 60); // tope: 60 años
    const proyectada = new Date(ahora.getTime() + diasRestantes * 86400000);
    texto.textContent = `Fecha estimada: ${fmtMesAnio.format(proyectada)}`;

    charts.proyeccionRoi = new Chart(el, {
        type: 'line',
        data: { labels: [fecha(primera), fecha(ahora), fecha(proyectada)], datasets: [
            { label: 'Ahorro proyectado', data: [0, ahorro, objetivo], borderColor: '#059669', borderDash: [5, 5], fill: false },
            { label: 'Objetivo', data: [objetivo, objetivo, objetivo], borderColor: '#4f46e5', pointRadius: 0, borderWidth: 1 }
        ] },
        options: { responsive: true, maintainAspectRatio: false,
            plugins: { tooltip: { callbacks: { label: (c) => `${c.dataset.label}: ${eur(c.parsed.y)}` } } },
            scales: { y: ejeEuros } }
    });
}

function renderSalud() {
    const el = $('chart-projection'); if (!el || !window.Chart) return;
    destruir('salud');
    const obd = [...appData.obd].filter((o) => !Number.isNaN(new Date(o.date).getTime())).sort((a, b) => new Date(a.date) - new Date(b.date));
    const destino = $('projection-date');

    if (obd.length >= 2) {
        const primera = obd[0], ultima = obd[obd.length - 1];
        const dias = (new Date(ultima.date) - new Date(primera.date)) / 86400000;
        const degradacion = primera.soh - ultima.soh;
        if (degradacion > 0 && dias > 0) {
            const diasHasta70 = (ultima.soh - 70) * (dias / degradacion);
            const fecha70 = new Date(new Date(ultima.date).getTime() + diasHasta70 * 86400000);
            destino.textContent = Number.isFinite(fecha70.getTime()) ? fmtMesAnio.format(fecha70) : 'Sin estimación';
        } else {
            destino.textContent = 'Degradación mínima';
        }
    } else {
        destino.textContent = 'Faltan datos';
    }

    charts.salud = new Chart(el, {
        type: 'line',
        data: { labels: obd.map((o) => fecha(o.date)), datasets: [{ label: 'SoH', data: obd.map((o) => o.soh), borderColor: '#4f46e5', tension: 0.3 }] },
        options: { responsive: true, maintainAspectRatio: false,
            plugins: { tooltip: { callbacks: { label: (c) => `SoH: ${pct(c.parsed.y)}` } } },
            scales: { y: { min: 70, max: 100, ticks: { callback: (v) => pct(v, 0) } } } }
    });
}

// ============================================================================
//  10. VALORACIÓN OBD
// ============================================================================
function valorarSaludObd() {
    const soh = leerNum('obd-soh');
    const mv = leerNum('obd-mv');
    const cap = leerNum('obd-cap');

    const elSoh = $('obd-fb-soh');
    if (soh === null || soh <= 0) elSoh.textContent = '';
    else if (soh > 90) { elSoh.textContent = 'Excelente'; elSoh.className = 'text-[11px] mt-1 font-bold min-h-[1rem] text-emerald-700 dark:text-emerald-400'; }
    else if (soh > 80) { elSoh.textContent = 'Bueno'; elSoh.className = 'text-[11px] mt-1 font-bold min-h-[1rem] text-blue-700 dark:text-blue-400'; }
    else if (soh > 70) { elSoh.textContent = 'Atención'; elSoh.className = 'text-[11px] mt-1 font-bold min-h-[1rem] text-orange-700 dark:text-orange-400'; }
    else { elSoh.textContent = 'Cubierto por garantía'; elSoh.className = 'text-[11px] mt-1 font-bold min-h-[1rem] text-red-700 dark:text-red-400'; }

    const elMv = $('obd-fb-mv');
    if (mv === null || mv <= 0) elMv.textContent = '';
    else if (mv <= 15) { elMv.textContent = 'Sano'; elMv.className = 'text-[11px] mt-1 font-bold min-h-[1rem] text-emerald-700 dark:text-emerald-400'; }
    else if (mv <= 30) { elMv.textContent = 'Vigilar'; elMv.className = 'text-[11px] mt-1 font-bold min-h-[1rem] text-orange-700 dark:text-orange-400'; }
    else { elMv.textContent = 'Desbalanceo'; elMv.className = 'text-[11px] mt-1 font-bold min-h-[1rem] text-red-700 dark:text-red-400'; }

    const elCap = $('obd-fb-cap');
    // Se compara con la capacidad configurada del coche, no con un 46 fijo.
    const capNominal = appData.settings.capacity;
    if (cap === null || cap <= 0 || capNominal <= 0) elCap.textContent = '';
    else {
        elCap.textContent = `Degradación: ${pct(((capNominal - cap) / capNominal) * 100)}`;
        elCap.className = 'text-[11px] mt-1 font-bold min-h-[1rem] text-slate-600 dark:text-slate-400';
    }
}

// ============================================================================
//  11. CALCULADORAS
// ============================================================================
function actualizarCalculadoras(origen = 'percent') {
    calcularEstimaciones(origen);
    calcularCargaCompleta();
    calcularTiempo80();
}

const modoRealista = () => $('toggle-factors')?.checked ?? true;

function factorCarga() {
    if (!modoRealista()) return 1;
    let f = 1;
    if ($('calc-factor-ac').checked) f *= 0.9;
    if ($('calc-factor-cold').checked) f *= 0.9;
    return f;
}

function factorConduccion() {
    if (!modoRealista()) return 1;
    let f = 1;
    if ($('calc-factor-ac').checked) f *= 0.9;
    if ($('calc-factor-highway').checked) f *= 0.85;
    if ($('calc-factor-cold').checked) f *= 0.9;
    return f;
}

function calcularEstimaciones(origen) {
    const soh = modoRealista() ? sohActual() / 100 : 1;
    const capacidad = appData.settings.capacity * soh;
    const alcance = appData.settings.wltp * soh * ((appData.settings.efficiency || 80) / 100) * factorConduccion();

    const eP = $('calc-input-percent'), eK = $('calc-input-kwh'), eD = $('calc-input-km');
    if (!eP || !eK || !eD) return;

    $('calc-info-cap').textContent = soh < 1 ? `Capacidad real (SoH ${pct(soh * 100)})` : 'Capacidad nominal';

    if (capacidad <= 0 || alcance <= 0) { eK.value = ''; eD.value = ''; return; }

    if (origen === 'percent') {
        const v = clamp(leerNum('calc-input-percent') ?? 0, 0, 100);
        eK.value = (capacidad * v / 100).toFixed(1);
        eD.value = Math.round(alcance * v / 100);
    } else if (origen === 'kwh') {
        const v = clamp(leerNum('calc-input-kwh') ?? 0, 0, capacidad);
        eP.value = ((v / capacidad) * 100).toFixed(1);
        eD.value = Math.round(alcance * (v / capacidad));
    } else {
        const v = clamp(leerNum('calc-input-km') ?? 0, 0, alcance);
        eP.value = ((v / alcance) * 100).toFixed(1);
        eK.value = (capacidad * (v / alcance)).toFixed(1);
    }
}

/** Curva de carga rápida del Opel Mokka-e (kW máximos según el SoC). */
const limiteCurvaCarga = (soc) => (soc < 30 ? 98 : soc < 55 ? 75 : soc < 75 ? 52 : soc < 80 ? 35 : soc < 90 ? 17 : 8);

function calcularCargaCompleta() {
    const inicio = clamp(leerNum('charge-start') ?? 0, 0, 100);
    const fin = clamp(leerNum('charge-end') ?? 0, 0, 100);
    const potencia = clamp(leerNum('charge-kw') ?? 0, 0.1, 400);
    const capacidad = appData.settings.capacity;
    const factor = factorCarga();

    let minutos = 0;
    // Bucle acotado a 0-100: antes un valor absurdo en el formulario podía colgar la pestaña.
    for (let i = Math.floor(inicio); i < Math.ceil(fin); i++) {
        let efectiva = potencia * factor;
        if (potencia > 11) efectiva = Math.min(efectiva, limiteCurvaCarga(i));
        minutos += ((capacidad * 0.01) / Math.max(efectiva, 0.1)) * 60;
    }

    $('charge-full-res').textContent = duracion(minutos);
    $('charge-net-power').textContent = factor < 1 ? `Potencia penalizada: ~${num(potencia * factor, 1)} kW` : 'Carga normal';
}

function calcularTiempo80() {
    const actual = clamp(leerNum('calc80-input') ?? 0, 0, 100);
    const potencia = clamp(leerNum('calc80-pwr') ?? 0, 0.1, 400);
    const capacidad = appData.settings.capacity;
    const res = $('calc80-res');
    if (actual >= 80) { res.textContent = 'Ya está listo'; return; }
    const horas = (capacidad * ((80 - actual) / 100)) / (potencia * factorCarga());
    res.textContent = duracion(horas * 60);
}

// ============================================================================
//  12. FORMULARIO DE RECARGAS
// ============================================================================
const CONSUMO_MEDIO_KWH_100KM = () => {
    const { capacity, wltp, efficiency } = appData.settings;
    const alcanceReal = wltp * ((efficiency || 80) / 100);
    return alcanceReal > 0 ? (capacity / alcanceReal) * 100 : 17;
};

const esModoLegacy = () => $('legacy-mode').checked;

function alternarModoLegacy() {
    const legacy = esModoLegacy();
    $('standard-fields').hidden = legacy;
    $('advanced-toggle-container').hidden = legacy;
    $('legacy-fields').hidden = !legacy;
    if (legacy) {
        $('advanced-fields').hidden = true;
        $('btn-advanced').setAttribute('aria-expanded', 'false');
        if ($('log-date').value) $('log-date-legacy').value = $('log-date').value;
    } else {
        $('adv-icon').classList.remove('rotate-90');
        if ($('log-date-legacy').value) $('log-date').value = $('log-date-legacy').value;
    }
    comprobarModoPublico();
}

function alternarAvanzados() {
    const zona = $('advanced-fields');
    const abierto = zona.hidden;
    zona.hidden = !abierto;
    $('btn-advanced').setAttribute('aria-expanded', String(abierto));
    $('adv-icon').classList.toggle('rotate-90', abierto);
}

function comprobarModoPublico() {
    const publica = $('log-loc').value === 'street' && !esModoLegacy();
    document.querySelectorAll('.public-only').forEach((e) => { e.hidden = !publica; });
    if (!publica) $('log-power').value = appData.settings.homePower;
    actualizarTarifaCasa();
}

function autoCalcularKwh() {
    const km = leerNum('log-km');
    if ($('log-kwh').value === '' && km !== null && km > 0) {
        $('log-kwh').value = (km / 100 * CONSUMO_MEDIO_KWH_100KM()).toFixed(2);
        recalcularCoste();
    }
}

function actualizarTarifaCasa() {
    const esCasa = $('log-loc').value === 'home' && !esModoLegacy();
    const insignia = $('auto-cost-badge');
    if (!esCasa) { insignia.hidden = true; return; }
    const valor = $('log-date').value;
    if (!valor) { insignia.hidden = true; return; }
    const d = new Date(valor);
    if (Number.isNaN(d.getTime())) { insignia.hidden = true; return; }
    const h = d.getHours(); // formato 24 h
    $('log-price-kwh').value = (h >= 1 && h < 7) ? appData.settings.pNight : appData.settings.pDay;
    insignia.hidden = false;
    recalcularCoste();
}

function recalcularCoste() {
    const kwh = leerNum('log-kwh'), precio = leerNum('log-price-kwh');
    if (kwh > 0 && precio > 0) $('log-cost').value = (kwh * precio).toFixed(2);
}

function recalcularPrecio() {
    const coste = leerNum('log-cost'), kwh = leerNum('log-kwh');
    if (kwh > 0 && coste > 0) $('log-price-kwh').value = (coste / kwh).toFixed(3);
}

// --- Validación con mensajes visibles -------------------------------------
function limpiarErrores(formId) {
    document.querySelectorAll(`#${formId} [data-error-for]`).forEach((p) => { p.textContent = ''; });
    document.querySelectorAll(`#${formId} [aria-invalid]`).forEach((i) => i.removeAttribute('aria-invalid'));
    const resumen = $(`${formId}-summary`);
    if (resumen) resumen.textContent = '';
}

function marcarError(id, mensaje) {
    const campo = $(id);
    const aviso = document.querySelector(`[data-error-for="${id}"]`);
    if (campo) campo.setAttribute('aria-invalid', 'true');
    if (aviso) aviso.textContent = mensaje;
    return { id, mensaje };
}

/** Valida un número dentro de un rango. Devuelve un error o null. */
function validarRango(id, etiqueta, { min = -Infinity, max = Infinity, obligatorio = false } = {}) {
    const v = leerNum(id);
    if (v === null) return obligatorio ? marcarError(id, `${etiqueta}: es obligatorio.`) : null;
    if (v < min || v > max) return marcarError(id, `${etiqueta}: debe estar entre ${num(min, 0)} y ${num(max, 0)}.`);
    return null;
}

function validarFormularioRecarga() {
    limpiarErrores('form-log');
    const errores = [];
    const legacy = esModoLegacy();

    if (legacy) {
        if (!$('log-date-legacy').value) errores.push(marcarError('log-date-legacy', 'Indica la fecha de la recarga.'));
        errores.push(validarRango('log-cost-legacy', 'Coste', { min: 0, max: 100000, obligatorio: true }));
        errores.push(validarRango('log-km-legacy', 'Kilómetros', { min: 0, max: 500000, obligatorio: true }));
    } else {
        if (!$('log-date').value) errores.push(marcarError('log-date', 'Indica la fecha y la hora.'));
        else if (Number.isNaN(new Date($('log-date').value).getTime())) errores.push(marcarError('log-date', 'La fecha no es válida.'));

        errores.push(validarRango('log-kwh', 'Energía', { min: 0, max: 500 }));
        errores.push(validarRango('log-cost', 'Coste total', { min: 0, max: 10000, obligatorio: true }));
        errores.push(validarRango('log-km', 'Kilómetros', { min: 0, max: 5000 }));
        errores.push(validarRango('log-soc-start', 'Batería al inicio', { min: 0, max: 100 }));
        errores.push(validarRango('log-soc-end', 'Batería al final', { min: 0, max: 100 }));
        errores.push(validarRango('log-odo-total', 'Odómetro', { min: 0, max: 2000000 }));
        errores.push(validarRango('log-power', 'Potencia', { min: 0, max: 400 }));
        errores.push(validarRango('log-duration', 'Duración', { min: 0, max: 10080 }));
        errores.push(validarRango('log-temp', 'Temperatura', { min: -40, max: 60 }));

        const ini = leerNum('log-soc-start'), fin = leerNum('log-soc-end');
        if (ini !== null && fin !== null && fin < ini) errores.push(marcarError('log-soc-end', 'El porcentaje final no puede ser menor que el inicial.'));
    }

    const reales = errores.filter(Boolean);
    if (reales.length) {
        $('form-log-summary').textContent = `Revisa ${reales.length === 1 ? 'el campo marcado' : `los ${reales.length} campos marcados`} en rojo.`;
        $(reales[0].id)?.focus();
    }
    return reales.length === 0;
}

/**
 * Minutos entre dos fechas ISO. null si falta alguna, no son válidas o el fin es anterior
 * al inicio. Sirve para rellenar solo la duración cuando ya se conocen la hora de enchufe
 * y la de desenchufe (las anota EVBot.py en `dateEnd`).
 */
function minutosEntre(inicio, fin) {
    if (!inicio || !fin) return null;
    const a = new Date(inicio).getTime(), b = new Date(fin).getTime();
    if (Number.isNaN(a) || Number.isNaN(b) || b < a) return null;
    return Math.floor((b - a) / 60000);
}

// Claves que rellena el formulario de recargas. Todo lo demás que traiga el registro
// (dateEnd, pendingFinal... los anota EVBot.py) hay que conservarlo: si no, editar el
// coste desde el panel borraba en silencio la hora de desenchufe.
const CAMPOS_FORMULARIO_LOG = ['id', 'date', 'km', 'kwh', 'cost', 'type', 'odo', 'power', 'duration',
    'precond', 'brand', 'temp', 'socStart', 'socEnd', 'subCost', 'iceCost', 'histIcePrice'];

function camposConservados(log) {
    const resto = {};
    for (const [clave, valor] of Object.entries(log || {})) {
        if (!CAMPOS_FORMULARIO_LOG.includes(clave)) resto[clave] = valor;
    }
    return resto;
}

function guardarRecarga(evento) {
    evento.preventDefault();
    if (!validarFormularioRecarga()) return;

    const id = editandoLogId ?? String(Date.now());
    let registro;

    if (esModoLegacy()) {
        registro = {
            id,
            date: $('log-date-legacy').value,
            km: leerNum0('log-km-legacy'),
            cost: leerNum0('log-cost-legacy'),
            iceCost: leerNum0('log-ice-cost'),
            type: 'legacy',
            histIcePrice: leerNum0('log-ice-price')
        };
    } else {
        const cuota = leerNum('log-sub-cost');
        registro = {
            id,
            date: $('log-date').value,
            km: leerNum0('log-km'),
            kwh: leerNum0('log-kwh'),
            cost: leerNum0('log-cost') + (cuota ?? 0),
            type: $('log-loc').value,
            odo: leerNum0('log-odo-total'),
            power: leerNum0('log-power'),
            duration: leerNum0('log-duration'),
            precond: $('log-precond').checked,
            brand: $('log-brand').value,
            temp: leerNum0('log-temp')
        };
        // Solo se guardan si el usuario los ha escrito: así 0 significa "0 %" y
        // no "sin dato" (antes toda recarga antigua salía como 0→0 en la gráfica).
        const ini = leerNum('log-soc-start'), fin = leerNum('log-soc-end');
        if (ini !== null) registro.socStart = ini;
        if (fin !== null) registro.socEnd = fin;
        if (cuota !== null && cuota > 0) registro.subCost = cuota;
    }

    if (editandoLogId) {
        const i = appData.logs.findIndex((x) => String(x.id) === String(editandoLogId));
        if (i !== -1) {
            registro = { ...camposConservados(appData.logs[i]), ...registro };
            if (registro.pendingFinal && registro.socEnd !== undefined) delete registro.pendingFinal;
            appData.logs[i] = registro;
        }
        cancelarEdicionRecarga();
        mostrarToast('Recarga actualizada');
    } else {
        appData.logs.push(registro);
        evento.target.reset();
        reiniciarFechasFormulario();
        alternarModoLegacy();
        mostrarToast('Recarga guardada');
    }
    guardarDatos();
    refrescarUI();
}

function editarRecarga(id) {
    const l = appData.logs.find((x) => String(x.id) === String(id));
    if (!l) return;
    editandoLogId = String(id);
    limpiarErrores('form-log');

    const legacy = l.type === 'legacy' || (Number.isFinite(l.iceCost) && l.iceCost > 0);
    $('legacy-mode').checked = legacy;
    alternarModoLegacy();

    if (legacy) {
        $('log-date-legacy').value = l.date;
        $('log-cost-legacy').value = l.cost;
        $('log-km-legacy').value = l.km;
        $('log-ice-price').value = l.histIcePrice ?? '';
        $('log-ice-cost').value = l.iceCost ?? '';
    } else {
        $('log-date').value = l.date;
        $('log-km').value = l.km;
        $('log-kwh').value = l.kwh ?? '';
        $('log-loc').value = l.type;
        $('log-cost').value = l.cost;
        $('log-price-kwh').value = l.kwh > 0 ? (l.cost / l.kwh).toFixed(3) : '';
        $('log-soc-start').value = l.socStart ?? '';
        $('log-soc-end').value = l.socEnd ?? '';
        $('log-odo-total').value = l.odo ?? '';
        $('log-power').value = l.power ?? '';
        // Si la carga la anotó el bot con hora de enchufe y de desenchufe, la duración
        // se deduce sola: mejor eso que dejar el campo vacío.
        $('log-duration').value = l.duration ?? minutosEntre(l.date, l.dateEnd) ?? '';
        $('log-precond').checked = Boolean(l.precond);
        $('log-brand').value = l.brand ?? '';
        $('log-sub-cost').value = l.subCost ?? '';
        $('log-temp').value = l.temp ?? '';
        comprobarModoPublico();
    }

    $('btn-submit').textContent = 'Actualizar recarga';
    $('btn-cancel').hidden = false;
    $('form-title').textContent = 'Editar recarga';
    $('form-log').scrollIntoView({ behavior: 'smooth', block: 'start' });
    anunciar('Editando una recarga existente');
}

function cancelarEdicionRecarga() {
    editandoLogId = null;
    $('form-log').reset();
    limpiarErrores('form-log');
    $('btn-submit').textContent = 'Guardar recarga';
    $('btn-cancel').hidden = true;
    $('form-title').textContent = 'Registrar recarga';
    $('legacy-mode').checked = false;
    alternarModoLegacy();
    reiniciarFechasFormulario();
}

function reiniciarFechasFormulario() {
    const ahora = ahoraLocalISO();
    $('log-date').value = ahora;
    $('log-date-legacy').value = ahora;
}

// ============================================================================
//  13. FORMULARIO OBD
// ============================================================================
function validarFormularioObd() {
    limpiarErrores('form-obd');
    const errores = [];
    if (!$('obd-date').value) errores.push(marcarError('obd-date', 'Indica la fecha de la lectura.'));
    errores.push(validarRango('obd-soh', 'SoH', { min: 0, max: 100, obligatorio: true }));
    errores.push(validarRango('obd-odo', 'Odómetro', { min: 0, max: 2000000 }));
    errores.push(validarRango('obd-cap', 'Capacidad', { min: 0, max: 500 }));
    errores.push(validarRango('obd-mv', 'Desbalanceo', { min: 0, max: 5000 }));
    errores.push(validarRango('obd-cycles', 'Ciclos', { min: 0, max: 100000 }));

    const reales = errores.filter(Boolean);
    if (reales.length) {
        $('form-obd-summary').textContent = `Revisa ${reales.length === 1 ? 'el campo marcado' : `los ${reales.length} campos marcados`} en rojo.`;
        $(reales[0].id)?.focus();
    }
    return reales.length === 0;
}

function guardarObd(evento) {
    evento.preventDefault();
    if (!validarFormularioObd()) return;

    const registro = {
        id: editandoObdId ?? String(Date.now()),
        date: $('obd-date').value,
        soh: leerNum0('obd-soh'),
        odo: leerNum0('obd-odo'),
        cap: leerNum0('obd-cap'),
        mv: leerNum0('obd-mv'),
        cycles: leerNum0('obd-cycles')
    };

    if (editandoObdId) {
        const i = appData.obd.findIndex((x) => String(x.id) === String(editandoObdId));
        if (i !== -1) appData.obd[i] = registro;
        cancelarEdicionObd();
        mostrarToast('Lectura OBD actualizada');
    } else {
        appData.obd.push(registro);
        evento.target.reset();
        $('obd-date').value = ahoraLocalISO(true);
        mostrarToast('Lectura OBD guardada');
    }
    guardarDatos();
    refrescarUI();
    renderSalud();
    renderTablaObd();
}

function editarObd(id) {
    const o = appData.obd.find((x) => String(x.id) === String(id));
    if (!o) return;
    editandoObdId = String(id);
    limpiarErrores('form-obd');
    $('obd-date').value = o.date;
    $('obd-soh').value = o.soh;
    $('obd-odo').value = o.odo;
    $('obd-cap').value = o.cap;
    $('obd-mv').value = o.mv;
    $('obd-cycles').value = o.cycles;
    $('btn-submit-obd').textContent = 'Actualizar';
    $('btn-cancel-obd').hidden = false;
    $('obd-form-title').textContent = 'Editar registro técnico (OBD)';
    valorarSaludObd();
    $('form-obd').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function cancelarEdicionObd() {
    editandoObdId = null;
    $('form-obd').reset();
    limpiarErrores('form-obd');
    $('btn-submit-obd').textContent = 'Guardar';
    $('btn-cancel-obd').hidden = true;
    $('obd-form-title').textContent = 'Nuevo registro técnico (OBD)';
    $('obd-date').value = ahoraLocalISO(true);
    valorarSaludObd();
}

// ============================================================================
//  14. TABLAS (todo el contenido dinámico va escapado)
// ============================================================================
function renderRecargas() {
    const cuerpo = $('logs-table');
    if (!cuerpo) return;

    const filas = [...appData.logs].sort((a, b) => new Date(b.date) - new Date(a.date)).map((l) => {
        const icono = l.type === 'legacy' ? 'fa-clock-rotate-left text-slate-500'
                    : l.type === 'home' ? 'fa-house text-indigo-500'
                    : 'fa-charging-station text-orange-500';
        const origen = l.brand || (l.type === 'home' ? 'Casa' : l.type === 'legacy' ? 'Histórico' : 'Pública');

        let extra = '';
        if (Number.isFinite(l.iceCost) && l.iceCost > 0) extra = '<span class="text-[11px] text-orange-600 dark:text-orange-400 block font-normal">Histórico</span>';
        else if (Number.isFinite(l.subCost) && l.subCost > 0) extra = `<span class="text-[11px] text-indigo-600 dark:text-indigo-400 block font-normal">Cuota: ${esc(eur(l.subCost))}</span>`;

        let soc = '—';
        if (Number.isFinite(l.socStart) && Number.isFinite(l.socEnd)) {
            const ganancia = l.socEnd - l.socStart;
            soc = `<div class="flex items-center gap-1 text-xs"><span class="text-slate-600 dark:text-slate-400">${esc(pct(l.socStart, 0))}</span>`
                + `<i class="fa-solid fa-arrow-right text-[10px] text-slate-500" aria-hidden="true"></i>`
                + `<span class="font-bold text-emerald-700 dark:text-emerald-400">${esc(pct(l.socEnd, 0))}</span></div>`
                + `<div class="text-[11px] text-emerald-700 dark:text-emerald-400 font-bold mt-0.5">${ganancia >= 0 ? '+' : ''}${esc(pct(ganancia, 0))}</div>`;
        }

        const detalleEnergia = (l.power || l.duration)
            ? `<div class="text-[11px] text-slate-600 dark:text-slate-400">${l.power ? esc(num(l.power, 1)) + ' kW' : ''}${l.power && l.duration ? ' · ' : ''}${l.duration ? esc(l.duration >= 60 ? duracion(l.duration) : num(l.duration) + ' min') : ''}</div>`
            : '';

        return `<tr class="border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/50">
            <td class="px-4 py-3">
                <div class="flex items-center gap-3">
                    <span class="w-8 h-8 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center flex-none"><i class="fa-solid ${icono}" aria-hidden="true"></i></span>
                    <span>
                        <span class="font-bold text-slate-800 dark:text-slate-100 text-sm block">${esc(fecha(l.date))}</span>
                        <span class="text-[11px] text-slate-600 dark:text-slate-400 font-medium uppercase tracking-wide">${esc(origen)}</span>
                    </span>
                </div>
            </td>
            <td class="px-4 py-3">
                <div class="text-sm text-slate-700 dark:text-slate-300"><b>${l.kwh ? esc(num(l.kwh, 1)) : '—'}</b> <span class="text-xs">kWh</span></div>${detalleEnergia}
            </td>
            <td class="px-4 py-3">
                <div class="text-sm text-slate-700 dark:text-slate-300"><b>${esc(num(l.km, 1))}</b> <span class="text-xs">km</span></div>
                ${l.odo ? `<div class="text-[11px] text-slate-600 dark:text-slate-400">Odo: ${esc(num(l.odo))}</div>` : ''}
            </td>
            <td class="px-4 py-3 hidden sm:table-cell">${soc}</td>
            <td class="px-4 py-3">
                <span class="font-black text-indigo-700 dark:text-indigo-300">${esc(eur(l.cost))}</span>
                ${(l.kwh > 0 && l.cost > 0) ? `<div class="text-[11px] text-slate-600 dark:text-slate-400">${esc(eur(l.cost / l.kwh, 3))}/kWh</div>` : ''}${extra}
            </td>
            <td class="px-4 py-3 text-center">
                <div class="row-actions flex justify-center gap-2">
                    <button type="button" data-action="edit-log" data-id="${esc(l.id)}" class="w-8 h-8 rounded-lg hover:bg-amber-50 dark:hover:bg-amber-900/20 text-slate-500 hover:text-amber-600" aria-label="Editar la recarga del ${esc(fecha(l.date))}"><i class="fa-solid fa-pen" aria-hidden="true"></i></button>
                    <button type="button" data-action="delete-log" data-id="${esc(l.id)}" class="w-8 h-8 rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 text-slate-500 hover:text-red-600" aria-label="Borrar la recarga del ${esc(fecha(l.date))}"><i class="fa-solid fa-trash" aria-hidden="true"></i></button>
                </div>
            </td>
        </tr>`;
    });

    cuerpo.innerHTML = filas.length ? filas.join('')
        : '<tr><td colspan="6" class="px-4 py-8 text-center text-slate-600 dark:text-slate-400">Todavía no hay recargas registradas.</td></tr>';
}

function renderTablaObd() {
    const cuerpo = $('obd-table');
    if (!cuerpo) return;

    const filas = [...appData.obd].sort((a, b) => new Date(b.date) - new Date(a.date)).map((o) => `
        <tr class="border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/50">
            <td class="px-6 py-4 font-bold text-slate-800 dark:text-slate-100">${esc(fecha(o.date))}</td>
            <td class="px-6 py-4 font-black text-indigo-700 dark:text-indigo-300">${esc(pct(o.soh))}</td>
            <td class="px-6 py-4 text-slate-700 dark:text-slate-300">${esc(num(o.odo))} km</td>
            <td class="px-6 py-4 text-slate-700 dark:text-slate-300">${esc(num(o.cap, 1))} kWh</td>
            <td class="px-6 py-4 text-center">
                <div class="row-actions flex justify-center gap-3">
                    <button type="button" data-action="edit-obd" data-id="${esc(o.id)}" class="w-8 h-8 rounded-lg text-slate-500 hover:text-amber-600" aria-label="Editar la lectura del ${esc(fecha(o.date))}"><i class="fa-solid fa-pen" aria-hidden="true"></i></button>
                    <button type="button" data-action="delete-obd" data-id="${esc(o.id)}" class="w-8 h-8 rounded-lg text-slate-500 hover:text-red-600" aria-label="Borrar la lectura del ${esc(fecha(o.date))}"><i class="fa-solid fa-trash" aria-hidden="true"></i></button>
                </div>
            </td>
        </tr>`);

    cuerpo.innerHTML = filas.length ? filas.join('')
        : '<tr><td colspan="5" class="px-6 py-8 text-center text-slate-600 dark:text-slate-400">Todavía no hay lecturas OBD.</td></tr>';
}

// ============================================================================
//  15. DIÁLOGOS
// ============================================================================
function abrirDialogo(dlg) {
    ultimoFoco = document.activeElement;
    dlg.showModal();
}
function cerrarDialogo(dlg) {
    if (dlg.open) dlg.close();
    ultimoFoco?.focus?.();
}

function pedirBorrado(tipo, id) {
    tipoPendienteBorrado = tipo;
    idPendienteBorrado = String(id);
    $('delete-desc').textContent = tipo === 'log'
        ? 'Se eliminará esta recarga. Esta acción no se puede deshacer.'
        : 'Se eliminará esta lectura OBD. Esta acción no se puede deshacer.';
    abrirDialogo($('delete-modal'));
}

function cerrarBorrado() {
    tipoPendienteBorrado = null;
    idPendienteBorrado = null;
    cerrarDialogo($('delete-modal'));
}

function confirmarBorrado() {
    if (tipoPendienteBorrado === 'log' && idPendienteBorrado !== null) {
        appData.logs = appData.logs.filter((x) => String(x.id) !== idPendienteBorrado);
        if (String(editandoLogId) === idPendienteBorrado) cancelarEdicionRecarga();
        guardarDatos();
        renderRecargas();
        actualizarPanel();
        mostrarToast('Recarga eliminada', 'fa-solid fa-trash text-red-400');
    } else if (tipoPendienteBorrado === 'obd' && idPendienteBorrado !== null) {
        appData.obd = appData.obd.filter((x) => String(x.id) !== idPendienteBorrado);
        if (String(editandoObdId) === idPendienteBorrado) cancelarEdicionObd();
        guardarDatos();
        renderSalud();
        renderTablaObd();
        actualizarPanel();
        mostrarToast('Lectura eliminada', 'fa-solid fa-trash text-red-400');
    }
    cerrarBorrado();
}

function abrirModalSeguridad(accion, contenido = null) {
    accionModal = accion;
    if (contenido) contenidoPendiente = contenido;
    const exportar = accion === 'export';
    $('modal-title').textContent = exportar ? 'Cifrar la copia de seguridad' : 'Desbloquear el archivo';
    $('modal-desc').textContent = exportar
        ? 'La contraseña es opcional, pero sin ella el archivo se guarda en claro. Se recomienda una frase larga.'
        : 'Introduce la contraseña con la que se cifró el archivo.';
    $('modal-action-btn').textContent = exportar ? 'Descargar' : 'Desbloquear';
    $('modal-pass').value = '';
    $('modal-pass').setAttribute('autocomplete', exportar ? 'new-password' : 'current-password');
    $('modal-pass-error').textContent = '';
    abrirDialogo($('security-modal'));
    $('modal-pass').focus();
}

function cerrarModalSeguridad() {
    $('modal-pass').value = '';   // no dejar la contraseña en el DOM
    contenidoPendiente = null;
    cerrarDialogo($('security-modal'));
}

function alternarVisibilidadPass() {
    const campo = $('modal-pass'), icono = $('pass-eye-icon'), boton = $('btn-toggle-pass');
    const visible = campo.type === 'text';
    campo.type = visible ? 'password' : 'text';
    icono.className = visible ? 'fa-solid fa-eye' : 'fa-solid fa-eye-slash';
    boton.setAttribute('aria-pressed', String(!visible));
}

function confirmarModalSeguridad() {
    if (accionModal === 'export') finalizarExportacion();
    else finalizarImportacion();
}

// ============================================================================
//  16. IMPORTACIÓN Y EXPORTACIÓN
// ============================================================================
function finalizarExportacion() {
    const pass = $('modal-pass').value;
    let contenido = JSON.stringify(appData);

    if (pass) {
        if (pass.length < 8) { $('modal-pass-error').textContent = 'Usa al menos 8 caracteres (recomendado: 12 o más).'; return; }
        try {
            contenido = JSON.stringify({ isEncrypted: true, content: CryptoJS.AES.encrypt(contenido, pass).toString() });
            claveSesion = pass;
        } catch (e) {
            $('modal-pass-error').textContent = 'No se ha podido cifrar el archivo.';
            console.error(e);
            return;
        }
    } else {
        if (!confirm('Vas a descargar la copia SIN CIFRAR. ¿Continuar?')) return;
        claveSesion = null;
    }

    enviarAlServidor(contenido);

    const url = URL.createObjectURL(new Blob([contenido], { type: 'application/json' }));
    const enlace = document.createElement('a');
    enlace.href = url;
    enlace.download = 'ev_backup.json';   // nombre esperado por el bot de Telegram
    document.body.appendChild(enlace);
    enlace.click();
    enlace.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);

    cerrarModalSeguridad();
    mostrarToast(pass ? 'Copia cifrada descargada' : 'Copia descargada sin cifrar', 'fa-solid fa-download text-emerald-400');
}

function finalizarImportacion() {
    const pass = $('modal-pass').value;
    if (!pass) { $('modal-pass-error').textContent = 'Introduce la contraseña.'; return; }
    if (!contenidoPendiente) { $('modal-pass-error').textContent = 'No hay ningún archivo pendiente.'; return; }

    try {
        const texto = CryptoJS.AES.decrypt(contenidoPendiente, pass).toString(CryptoJS.enc.Utf8);
        if (!texto) throw new Error('descifrado vacío');
        appData = normalizarDatos(JSON.parse(texto));
        claveSesion = pass;
        guardarDatos();
        cerrarModalSeguridad();
        restaurarBotonServidor();
        refrescarUI();
        mostrarToast('Archivo desbloqueado e importado', 'fa-solid fa-unlock text-emerald-400');
    } catch (e) {
        $('modal-pass-error').textContent = 'La contraseña no es correcta o el archivo está dañado.';
    }
}

function seleccionarArchivo(input) {
    const archivo = input.files?.[0];
    if (!archivo) return;
    if (archivo.size > MAX_BYTES_IMPORT) { alert('El archivo es demasiado grande (máximo 8 MB).'); input.value = ''; return; }

    const lector = new FileReader();
    lector.onerror = () => { alert('No se ha podido leer el archivo.'); input.value = ''; };
    lector.onload = (e) => {
        try {
            const contenido = JSON.parse(String(e.target.result));
            if (contenido && contenido.isEncrypted && typeof contenido.content === 'string') {
                abrirModalSeguridad('import', contenido.content);
            } else if (confirm('¿Cargar este archivo? Se sustituirán todos los datos actuales.')) {
                appData = normalizarDatos(contenido);
                claveSesion = null;
                guardarDatos();
                refrescarUI();
                mostrarToast('Datos importados', 'fa-solid fa-file-import text-emerald-400');
            }
        } catch (err) {
            alert('El archivo no contiene un JSON válido.');
        } finally {
            input.value = '';
        }
    };
    lector.readAsText(archivo);
}

function restaurarBotonServidor() {
    const btn = $('server-status');
    if (!btn) return;
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-server" aria-hidden="true"></i> <span id="server-status-text">Recargar del NAS</span>';
}

async function cargarDelServidor(manual = false) {
    if (location.protocol === 'file:') return;
    const btn = $('server-status');
    try {
        if (manual && btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> Conectando…'; }

        const res = await fetch('ev_backup.json?t=' + Date.now(), { cache: 'no-store' });
        if (!res.ok) { if (manual) { alert('No se ha encontrado ev_backup.json en el servidor.'); restaurarBotonServidor(); } return; }

        const contenido = await res.json();

        if (contenido && contenido.isEncrypted && typeof contenido.content === 'string') {
            contenidoPendiente = contenido.content;
            abrirModalSeguridad('import');
            $('modal-desc').textContent = 'Se ha detectado una copia cifrada en el NAS. Introduce la contraseña.';
            restaurarBotonServidor();
            return;
        }

        if (contenido && contenido.settings && Array.isArray(contenido.logs)) {
            if (manual && !confirm('¿Recargar desde el NAS? Se perderán los cambios locales no guardados.')) { restaurarBotonServidor(); return; }
            appData = normalizarDatos(contenido);
            claveSesion = null;
            guardarDatos();
            refrescarUI();
            restaurarBotonServidor();
            mostrarToast('Datos cargados del NAS', 'fa-solid fa-server text-emerald-400');
            btn?.classList.remove('hidden');
        } else if (manual) {
            alert('El archivo del servidor no tiene el formato esperado.');
            restaurarBotonServidor();
        }
    } catch (e) {
        if (manual) { alert('No se ha podido contactar con el servidor.'); restaurarBotonServidor(); }
    }
}

// ============================================================================
//  17. REFRESCO GENERAL
// ============================================================================
function refrescarUI() {
    cargarConfig();
    aplicarTemaAGraficas();
    actualizarPanel();
    renderRecargas();
    if (!$('view-health').hidden) { renderSalud(); renderTablaObd(); }
    actualizarCalculadoras();
}

// ============================================================================
//  18. ARRANQUE Y EVENTOS (sin un solo onclick en el marcado)
// ============================================================================
const ACCIONES = {
    'toggle-theme': alternarTema,
    'reload-server': () => cargarDelServidor(true),
    'chart-mode': (btn) => {
        modoGrafica = btn.dataset.mode === 'annual' ? 'annual' : 'cumulative';
        $('btn-chart-cumulative').setAttribute('aria-pressed', String(modoGrafica === 'cumulative'));
        $('btn-chart-annual').setAttribute('aria-pressed', String(modoGrafica === 'annual'));
        $('btn-chart-cumulative').className = 'px-3 py-1 text-xs font-bold rounded-md ' + (modoGrafica === 'cumulative' ? 'bg-white dark:bg-slate-700 shadow-sm text-indigo-700 dark:text-white' : 'text-slate-600 dark:text-slate-300');
        $('btn-chart-annual').className = 'px-3 py-1 text-xs font-bold rounded-md ' + (modoGrafica === 'annual' ? 'bg-white dark:bg-slate-700 shadow-sm text-indigo-700 dark:text-white' : 'text-slate-600 dark:text-slate-300');
        renderGraficaPrincipal();
    },
    'toggle-advanced': alternarAvanzados,
    'cancel-log': cancelarEdicionRecarga,
    'cancel-obd': cancelarEdicionObd,
    'edit-log': (btn) => editarRecarga(btn.dataset.id),
    'delete-log': (btn) => pedirBorrado('log', btn.dataset.id),
    'edit-obd': (btn) => editarObd(btn.dataset.id),
    'delete-obd': (btn) => pedirBorrado('obd', btn.dataset.id),
    'close-delete': cerrarBorrado,
    'confirm-delete': confirmarBorrado,
    'close-security': cerrarModalSeguridad,
    'confirm-security': confirmarModalSeguridad,
    'toggle-pass': alternarVisibilidadPass,
    'export': () => abrirModalSeguridad('export'),
    'preset-iberdrola': aplicarPresetIberdrola
};

function iniciar() {
    aplicarTemaAGraficas();
    cargarConfig();

    // Delegación de eventos: ningún manejador inline en el HTML.
    document.addEventListener('click', (e) => {
        const boton = e.target.closest('[data-action]');
        if (!boton) return;
        const accion = ACCIONES[boton.dataset.action];
        if (accion) { e.preventDefault(); accion(boton); }
    });

    // Pestañas accesibles (ratón + teclado)
    const tabs = PESTANAS.map((p) => $('tab-' + p));
    tabs.forEach((tab, i) => {
        tab.addEventListener('click', () => cambiarPestana(PESTANAS[i]));
        tab.addEventListener('keydown', (e) => {
            const salto = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : e.key === 'Home' ? -i : e.key === 'End' ? tabs.length - 1 - i : 0;
            if (!salto) return;
            e.preventDefault();
            cambiarPestana(PESTANAS[(i + salto + tabs.length) % tabs.length], true);
        });
    });

    // Configuración
    document.querySelectorAll('[data-config]').forEach((el) => {
        el.addEventListener('change', guardarConfig);
        if (el.type === 'range') el.addEventListener('input', () => { $('eff-val-label').textContent = pct(leerNum0('conf-eff'), 0); });
    });

    // Calculadora
    $('calc-input-percent').addEventListener('input', () => actualizarCalculadoras('percent'));
    $('calc-input-kwh').addEventListener('input', () => actualizarCalculadoras('kwh'));
    $('calc-input-km').addEventListener('input', () => actualizarCalculadoras('km'));
    ['calc-factor-ac', 'calc-factor-highway', 'calc-factor-cold', 'toggle-factors']
        .forEach((id) => $(id).addEventListener('change', () => actualizarCalculadoras('percent')));
    ['charge-start', 'charge-end', 'charge-kw'].forEach((id) => $(id).addEventListener('input', calcularCargaCompleta));
    ['calc80-input', 'calc80-pwr'].forEach((id) => $(id).addEventListener('input', calcularTiempo80));

    // Formulario de recargas
    $('form-log').addEventListener('submit', guardarRecarga);
    $('legacy-mode').addEventListener('change', alternarModoLegacy);
    $('log-loc').addEventListener('change', comprobarModoPublico);
    $('log-date').addEventListener('change', actualizarTarifaCasa);
    $('log-kwh').addEventListener('input', () => { recalcularCoste(); actualizarTarifaCasa(); });
    $('log-km').addEventListener('input', autoCalcularKwh);
    $('log-price-kwh').addEventListener('input', recalcularCoste);
    $('log-cost').addEventListener('input', recalcularPrecio);

    // Formulario OBD
    $('form-obd').addEventListener('submit', guardarObd);
    ['obd-soh', 'obd-mv', 'obd-cap'].forEach((id) => $(id).addEventListener('input', valorarSaludObd));

    // Importación
    $('import-file').addEventListener('change', (e) => seleccionarArchivo(e.target));

    // Diálogos: Escape y clic fuera
    $('security-modal').addEventListener('cancel', (e) => { e.preventDefault(); cerrarModalSeguridad(); });
    $('delete-modal').addEventListener('cancel', (e) => { e.preventDefault(); cerrarBorrado(); });
    $('delete-modal').addEventListener('click', (e) => { if (e.target === $('delete-modal')) cerrarBorrado(); });

    // Valores iniciales de fecha (hora local, no UTC)
    reiniciarFechasFormulario();
    $('obd-date').value = ahoraLocalISO(true);

    comprobarModoPublico();
    refrescarUI();
    cargarDelServidor(false);
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', iniciar);
else iniciar();

})();
</script>
</body>
</html>
