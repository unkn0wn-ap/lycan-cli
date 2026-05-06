<div align="center">
<pre>
  _  __  ___   _   _   ___   _  _   
 | |/ / |_ _| | | | | / __| | \| |  
 | ' <   | |  | |_| || (__  | .` |  
  \_/\_\ |_|   \__, | \___| |_|\_|  
  __  __  ___   |___/ __  _ _  ___ 
 / _|/ _||  _| / __| | || | | | _ \
|__ \\__ \| _| | (__  | |_| | |  _/
|___/|___/|___|  \___|  \___/  |_|  
</pre>
  <h3>Latencia Cero. Evidencia Criptográfica. Reconocimiento Total.</h3>
</div>

---

**Lycan Security Agent** es la herramienta CLI de escaneo de vulnerabilidades local de próxima generación. Diseñada bajo el paradigma BYOI (*Bring Your Own Infrastructure*), se conecta en tiempo real a la plataforma Lycan Security para despachar y procesar auditorías de seguridad sin necesidad de abrir puertos entrantes ni configurar redes complejas.

## 🚀 Instalación One-Liner

Instala el agente y todas sus dependencias críticas (`nmap`, `sqlmap`, `curl`) de forma universal en Linux o macOS:

```bash
curl -sSL https://raw.githubusercontent.com/unkn0wn-ap/lycan-cli/main/install.sh | bash
```

## 🔒 Seguridad e Integridad (HMAC-SHA256)

La credibilidad de una auditoría depende de la inalterabilidad de sus pruebas. **Lycan Security Agent** asegura esto mediante el uso de firmas criptográficas:
* **Firma Automática:** Cada hallazgo de vulnerabilidad o extracción de evidencia (ej. banners de base de datos) es firmado en el propio agente usando **HMAC-SHA256** con la llave maestra del usuario.
* **Inalterabilidad:** Esto garantiza que los resultados no pueden ser modificados en tránsito (Man-in-the-Middle) ni manipulados posteriormente en la base de datos central de Lycan. La evidencia capturada tiene garantía absoluta de origen y estado.

## 💻 Comandos Principales

Una vez instalado, controla el agente utilizando el alias global `lycan`.

| Comando | Acción |
|---------|--------|
| `lycan setup` | 🔑 **Configuración Inicial:** Asistente interactivo para registrar de forma segura tu API Key y credenciales de entorno en `~/.lycan/config.json`. |
| `lycan start` | 🟢 **Ejecución Activa:** Arranca el demonio del agente y espera órdenes en tiempo real de la plataforma Lycan. |
| `lycan config` | ⚙️ **Auditoría de Entorno:** Muestra la configuración actual y estado de credenciales activas (con ofuscación de secretos). |
| `lycan install-deps` | 📦 **Resolución de Dependencias:** Fuerza la reinstalación local de herramientas ofensivas como `nmap` y `sqlmap` mediante tu gestor de paquetes (`apt`, `brew`, `pacman`, `dnf`). |

## ⚠️ Disclaimer Legal

**ADVERTENCIA:** Este agente es una herramienta ofensiva capaz de interactuar activamente con redes e infraestructuras, extrayendo datos y ejecutando cargas útiles de comprobación. Su uso está estrictamente limitado a infraestructuras, redes y aplicaciones web para las que usted posea **autorización expresa y por escrito** para auditar. Todo el uso corre por su cuenta y riesgo. Los desarrolladores de Lycan Security no asumen responsabilidad alguna por mal uso o daño causado por esta herramienta.

---

<div align="center">
  <b>Built for offensive scale.</b><br>
  Lycan Security © 2026
</div>
