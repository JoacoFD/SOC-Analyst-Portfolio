# Análisis de Tráfico de Red: Detección de Reconocimiento

Como parte de mis laboratorios de SOC, realicé un análisis de tráfico utilizando **Wireshark** para identificar patrones de ataque a nivel de red (Capa 4 del modelo OSI). La capacidad de identificar un escaneo antes de que se convierta en una intrusión es vital para un Analista SOC.

## 1. Detección de Escaneo de Puertos (TCP SYN Scan)

Durante el monitoreo, identifiqué una ráfaga anómala de paquetes provenientes de una única dirección IP dirigiéndose a múltiples puertos en un intervalo de tiempo extremadamente reducido.

### Detalle del Análisis:
* **Filtro Aplicado:** `tcp.flags.syn == 1 and tcp.flags.ack == 0`
* **IP Origen (Atacante):** 192.168.100.94
* **IP Destino (Objetivo):** 179.61.89.7
* **Protocolo:** TCP

### Evidencia Visual:
En la siguiente captura se observa el patrón de "Half-Open Scan". El atacante envía paquetes **SYN** para verificar si un puerto está abierto, pero no completa el saludo de tres vías (Three-way Handshake), lo que confirma una fase de enumeración activa por herramientas como Nmap.

<img width="1875" height="878" alt="image" src="https://github.com/user-attachments/assets/4e4bb5ef-c333-406e-96d1-27f01750979b" />


---

## 2. Conclusiones para el SOC
* **Táctica MITRE:** Reconocimiento (T1595).
* **Indicadores de Compromiso (IoCs):** Se identificó la IP atacante y el rango de puertos sondeados (443, 10000, 1025, 1026, entre otros).
* **Recomendación de Mitigación:** Implementar reglas en el Firewall o IPS para bloquear o limitar el tráfico de IPs que generen una cantidad inusual de paquetes SYN en poco tiempo (Threshold-based alerting).
