# Reporte Técnico de Laboratorio: Attacktive Directory
**Plataforma:** TryHackMe  
**Enfoque:** Simulación de Adversario y Análisis de Detección (Blue Team)

---

## 1. Objetivo del Proyecto
El propósito de este laboratorio es identificar y explotar vulnerabilidades críticas en un entorno de **Active Directory (AD)** basado en Windows. El análisis se centra en el compromiso de la cadena de autenticación de Kerberos y la escalada de privilegios, proporcionando una visión desde la perspectiva del **Analista SOC** para identificar Indicadores de Compromiso (IoCs) y proponer medidas de mitigación efectivas.

## 2. Metodología de Seguridad
Se sigue un enfoque basado en el framework **MITRE ATT&CK**, cubriendo las fases de Reconocimiento, Acceso Inicial y Enumeración de privilegios.

---

## 3. Fase 1: Reconocimiento y Análisis de Superficie de Ataque
Se ejecutó un escaneo de red exhaustivo para mapear los servicios del Controlador de Dominio (DC).

### Evidencia Técnica:
**Comando ejecutado:**
`nmap -p- --open -sS -sC -sV --min-rate 5000 -vvv -n -Pn 10.65.152.175`


<img width="1918" height="930" alt="image" src="https://github.com/user-attachments/assets/8776a4ff-d34f-42ee-84a4-3e89f6825ba0" />


### Análisis de Exposición:
* **Identificación de Activos:** La exposición de los puertos **88 (Kerberos)**, **389 (LDAP)** y **445 (SMB)** confirma que el activo es un Controlador de Dominio (Tier 0) para el dominio `spookysec.local`.
* **Vulnerabilidad de Enumeración:** El servicio LDAP y SMB permiten obtener información sobre la estructura de objetos del dominio, mientras que Kerberos permite validar usuarios mediante ataques de fuerza bruta.
* **Detección de Intrusos:** Un escaneo con `--min-rate 5000` es altamente ruidoso y dispararía alertas de **"Port Scanning"** en un sistema de monitoreo. Como analista SOC, este es el primer IoC (Indicador de Compromiso) a investigar.

---

## 4. Fase 2: Enumeración de Usuarios (Kerberos Brute Force)


En esta fase se realizó una enumeración de usuarios válida contra el KDC (Key Distribution Center) utilizando la herramienta **Kerbrute**. Esta técnica es fundamental para identificar cuentas existentes sin alertar bloqueos de cuenta por contraseñas incorrectas.

### Evidencia Técnica:
Se utilizó un diccionario de usuarios y se configuraron hilos optimizados para el entorno. Se identificaron múltiples cuentas válidas, destacando `svc-admin` con la etiqueta **[NOT PREAUTH]**, lo que indica una vulnerabilidad crítica de configuración.

**Comando ejecutado:**
`python3 kerbrute.py -users userlist.txt -passwords passwordlist.txt -domain spookysec.local -t 100`


<img width="918" height="295" alt="Captura de pantalla 2026-01-11 220015" src="https://github.com/user-attachments/assets/af119aaf-5d26-432f-a8b0-066602601bec" />



### Análisis SOC (Detección y Eventos):
Desde la perspectiva de monitoreo, este ataque genera ruido específico en el Controlador de Dominio que debe ser alertado en un SIEM:

* **Event ID 4768 (TGT Request):** Se genera cada vez que Kerbrute valida un usuario existente. Un volumen inusual de este evento desde una sola IP de origen es un IoC (Indicador de Compromiso) claro.
* **Event ID 4771 (Kerberos pre-authentication failed):** Aparece cuando se intenta validar un usuario que no existe o con datos erróneos. El analista debe buscar el código de error `0x6` (cliente no encontrado en la base de datos de AD).
* **Identificación Crítica:** El usuario `svc-admin` permite solicitudes sin pre-autenticación, lo que expone al dominio a ataques de **AS-REP Roasting**.

---

## 5. Fase 3: Acceso Inicial (AS-REP Roasting)

Al haber identificado que `svc-admin` no requiere pre-autenticación de Kerberos, se procedió a extraer el hash del Ticket Granting Response (AS-REP) para su posterior crackeo offline.

### Evidencia Técnica:
**Comando ejecutado:**
`impacket-GetNPUsers spookysec.local/svc-admin -no-pass`


<img width="1491" height="162" alt="Captura de pantalla 2026-01-11 221943" src="https://github.com/user-attachments/assets/08ecfb28-d7e8-4c43-966d-3ce3bf666efd" />



### Análisis de Riesgo:
* **Vulnerabilidad:** Configuración débil en la cuenta de servicio.
* **Detección SOC:** Monitorear solicitudes de tickets AS-REQ que no incluyan el campo de pre-autenticación, especialmente si utilizan tipos de cifrado antiguos como **RC4 (0x17)**, visibles en el tráfico de red o logs detallados de Kerberos.
## 5. Fase 3: Acceso Inicial - AS-REP Roasting
Tras identificar que el usuario `svc-admin` tiene la propiedad `DONT_REQ_PREAUTH` activada, procedí a realizar un ataque de **AS-REP Roasting** utilizando `GetNPUsers.py` para obtener el hash de su ticket Kerberos.

## 6. Fase 4: Cracking Offline de Credenciales
Utilicé **John the Ripper** con el diccionario `rockyou.txt` para descifrar el hash obtenido. El proceso fue exitoso debido al uso de un cifrado vulnerable.

### Evidencia Técnica:
**Comando ejecutado:**
`john --wordlist=/usr/share/wordlists/rockyou.txt hash`


<img width="900" height="185" alt="Captura de pantalla 2026-01-11 222548" src="https://github.com/user-attachments/assets/14989fd0-c737-4993-8613-09572e97113d" />


* **Usuario:** `svc-admin`
* **Contraseña Identificada:** `management2005`

---

## 🛡️ 7. Análisis de Detección 
Como analista de seguridad, la importancia de este laboratorio no es solo el acceso, sino la capacidad de detectar estas trazas en los **Logs Crudos** del sistema.

### Eventos Críticos Identificados:
| Event ID | Descripción | Significado Forense |
| :--- | :--- | :--- |
| **4771** | Kerberos Pre-Auth Failed | Generado masivamente durante la fase de enumeración (Kerbrute). El código de error `0x6` indica usuarios inexistentes. |
| **4768** | TGT Request | Registrado cuando solicité el hash de `svc-admin`. El campo de pre-autenticación aparece como "0" (no requerida). |

### Recomendaciones de Endurecimiento (Hardening):
1. **Remediación Inmediata:** Desactivar la opción "Do not require Kerberos preauthentication" en la cuenta `svc-admin`.
2. **Mejora de Cifrado:** Forzar el uso de **AES-256** para Kerberos, deshabilitando RC4 y DES a nivel de dominio para dificultar el cracking offline.
3. **Monitoreo:** Implementar alertas en el SIEM para el Event ID 4768 cuando el tipo de cifrado sea **0x17** (RC4).

## 🛡️ 8. Conclusiones y Estrategia de Defensa 

Como resultado de este laboratorio, se concluye que la mala configuración de cuentas (específicamente la desactivación de la pre-autenticación de Kerberos) representa un riesgo crítico de compromiso de identidad. Para mitigar estos riesgos en un entorno empresarial, se proponen las siguientes acciones:

### A. Plan de Remediación (Hardening)
1. **Auditoría de Cuentas:** Ejecutar un script de PowerShell periódicamente para identificar cuentas con el atributo `DONT_REQ_PREAUTH` activo y forzar la pre-autenticación.
2. **Actualización de Protocolos:** Deshabilitar los tipos de cifrado débiles (RC4) y forzar el uso exclusivo de AES-256 para los tickets de Kerberos.
3. **Políticas de Contraseñas:** Implementar políticas de longitud y complejidad para mitigar el éxito de ataques de cracking offline como el demostrado con `John the Ripper`.

### B. Reglas de Correlación para el SIEM
Para una detección proactiva, recomiendo la implementación de las siguientes lógicas en el sistema de monitoreo:

* **Alerta de AS-REP Roasting:** Generar una alerta de severidad **Alta** si se detecta un **Event ID 4768** donde el campo `Pre-Auth Type` sea `0` y el `Ticket Encryption` sea `0x17`.
* **Alerta de Enumeración (Brute Force):** Generar una alerta de severidad **Media** si una única dirección IP de origen genera más de 20 eventos **4771** (Fallo de pre-autenticación) en un lapso de 5 minutos.
