# Lycan Distributed Agent (BYOI)

Manual breve para ejecutar el agente local de escaneo.

## 1) Construir la imagen Docker

Desde la carpeta `backend`, ejecuta:

```bash
docker build -t lycan-agent ..
```

## 2) Ejecutar el contenedor

El agente requiere estas variables:

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `LYCAN_API_KEY`

Comando de ejemplo:

```bash
docker run -d --restart unless-stopped --name lycan-agent \
  -e SUPABASE_URL="https://TU-PROYECTO.supabase.co" \
  -e SUPABASE_ANON_KEY="TU_SUPABASE_ANON_KEY" \
  -e LYCAN_API_KEY="TU_LYCAN_API_KEY" \
  lycan-agent
```

## 3) Requisito de red

El agente necesita salida a internet por el puerto **443/TCP** para:

- comunicarse con Supabase
- ejecutar resolución/consultas externas de los escaneos

Si el puerto 443 está bloqueado por firewall/proxy, el agente no podrá operar correctamente.
