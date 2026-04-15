# NetRisk Analyzer

A Flask-based web application that logs user IP addresses and analyzes their risk level based on proxy, VPN, Tor, and hosting detection.

The system collects IP data, assigns a risk score, and stores logs in a PostgreSQL database as well as local JSON and text files.

---

## Features

- IP address logging 
- Risk analysis based on external IP intelligence API
- Detection of proxy, VPN, Tor, and hosting IPs
- Risk scoring system (LOW / MEDIUM / HIGH)
- Data storage in PostgreSQL, JSON, and text logs
- Simple frontend dashboard showing request history

---

## Technologies

- Python (flask)
- PostgreSQL
- JavaScript 
- HTML / CSS
- Requests / dotenv

---

## API

- `GET /API/get_ip_logs` – returns logs for current IP session
- `GET /ip/<ip>` – returns detailed logs for a specific IP (token required)

---

## Notes

This project is for educational purposes and demonstrates backend development, API usage, and basic security analysis concepts.