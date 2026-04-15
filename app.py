from flask import Flask, request, render_template, session, jsonify 
import dotenv 
import requests 
import psycopg2 
from datetime import datetime, timezone 
import os 
import json

dotenv.load_dotenv()

app = Flask(__name__) # assign app variable
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

token = os.getenv("TOKEN") # get your ipinfo.io authorization token from the .env file

app_auth_token = os.getenv("APP_AUTHORIZATION_TOKEN")

path_name = 'logs.json'

def database_connect(db_name):
    conn = psycopg2.connect(
        host = 'localhost',
        database = db_name,
        user = os.getenv('DATABASE_USER'),
        password = os.getenv('DATABASE_PASSWORD')
    )
    cur = conn.cursor()
    return conn, cur
    

@app.before_request 
def log():
    endpoint = request.path 
    skip = ['/script.js', '/favicon.ico', '/.well-known/appspecific/com.chrome.devtools.json']
    if endpoint.startswith("/static") or endpoint.startswith("/API/get_ip_logs") or endpoint in skip: 
        return # Used to prevent logging GETs such as: "/static/js/script.js"
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) # get ip
    session['ip'] = ip

    response = requests.get(f"https://v2.api.iphub.info/ip/{ip}", headers={"X-Key": token})
    data = response.json()

    data = {
        "hostname": "dns.google", 
        "ip": "8.8.8.8",
        "asn": 15169,
        "isp": "GOOGLE",
        "countryCode": "US",
        "countryName": "United States",
        "block": 1,
        "blockReason": "Hosting, proxy or bad IP",
        "proxyType": {
            "proxy": True,
            "tor": False,
            "hosting": True,
            "relay": False,
            "residentialProxy": False,
            "cloudGaming": False
        }
    }

    isp = data.get('isp')
    country = data.get('countryName')
    blockReason = data.get('blockReason')
    proxyType = data.get('proxyType') or {}
    isProxy = proxyType.get('proxy', False)
    isTor = proxyType.get('tor', False)
    isHosting = proxyType.get('hosting', False)
    isRelay = proxyType.get('relay', False)
    isResidentialProxy = proxyType.get("residentialProxy", False)
    isCloudGaming = proxyType.get('cloudGaming', False)

    score = 0
    if blockReason:
        if 'tor' in blockReason.lower():
            score += 5
        elif 'proxy' in blockReason.lower():
            score += 3
        else:
            score += 2
    # check for potential proxies / VPNs
    if isProxy:
        score += 3
    if isTor:
        score += 8
    if isResidentialProxy:
        score += 6

    if isHosting:
        score += 2
    if isRelay:
        score += 3

    if isCloudGaming:
        score += 2 
    
    if isHosting and isResidentialProxy:
        score += 2
    if isHosting and isProxy:
        score += 2

    if score <= 3:
        risk = 'LOW'
    elif score <= 7:
        risk = "MEDIUM"
    else:
        risk = "HIGH"  
    
    date = datetime.now(timezone.utc)

    # IF DATABASE AVAILABLE - RECOMMENDED
    conn, cur = database_connect('logs')

    try:
        cur.execute(
            """INSERT INTO ip_logs (ip, endpoint, country, date, isproxy, istor, blocks, ishosting, isresidentialproxy, iscloudgaming, isrelay, risk_score, risk_level, isp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (ip, endpoint, country, date, isProxy, isTor, blockReason, isHosting, isResidentialProxy, isCloudGaming, isRelay, score, risk, isp)
        )
        conn.commit()
    except Exception as e:
        print(f"Error - {e}")
        conn.rollback()
    finally:
        conn.close()

    # you can use JSON as well
    if os.path.exists(path_name):
        try:
            with open(path_name, 'r') as f:
                reader = json.load(f)
        except json.JSONDecodeError:
            reader = []
    else:
        reader = []
    
    save_json = {"Endpoint": endpoint, "Country": country, "ISP": isp, "Date": date.isoformat(), "Proxy": isProxy, "Tor": isTor, "Block Reason": blockReason, "Hosting": isHosting, "Residential Proxy": isResidentialProxy, "Cloud Gaming": isCloudGaming, "Relay": isRelay, "Score": score, "Risk": risk}
    reader.append({ip: save_json})

    with open('logs.json', 'w') as j:
        json.dump(reader, j, indent=4)
    

    # or save all the data in a .txt file
    save_file = f"IP - {ip} | Endpoint - {endpoint} | Country - {country} | ISP - {isp} | Date - {date} \n| Proxy - {isProxy} | Tor - {isTor} | Block Reason - {blockReason} | Hosting - {isHosting} | Residential Proxy - {isResidentialProxy} | Cloud Gaming - {isCloudGaming} | Relay - {isRelay} | Score - {score} | Risk - {risk}\n\n"
    with open('logs.txt', 'a') as f:
        f.write(save_file)


@app.route('/API/get_ip_logs')
def get_logs():
    ip = session.get('ip')
    conn, cur = database_connect('logs')
    try:
        cur.execute(
        "SELECT endpoint, country, date, risk_score, risk_level FROM ip_logs WHERE ip = %s ORDER BY date ASC",
            (ip,)
        )
        rows = cur.fetchall()
        data = []
        for row in rows:
            data.append({
                "endpoint": row[0],
                "country": row[1],
                "date": row[2].replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S"),
                "risk_score": row[3],
                "risk_level": row[4]
            })
        print(data)
        return jsonify(data=data, ip=ip)
    finally:
        conn.close()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/ip/<ip>")
def ip_route(ip):
    # simple token-based auth (header or query param)
    auth_token = request.args.get("Authorization")
    if request.headers.get("Authorization") != app_auth_token and auth_token != app_auth_token:
        return jsonify({'error': 'Unauthorized'}), 401
    conn, cur = database_connect('logs') 
    try:
        cur.execute(
            """SELECT endpoint, country, date, isproxy, istor, blocks, ishosting, isresidentialproxy, iscloudgaming, isrelay, risk_score, risk_level, isp FROM ip_logs WHERE ip = %s ORDER BY date ASC""",
            (ip,)
        )
        rows = cur.fetchall()
        data = []
        for row in rows:
            d = {}
            d['endpoint'] = row[0]
            d['country'] = row[1]
            d['isp'] = row[12]
            d['isproxy'] = row[3]
            d['istor'] = row[4]
            d['blocks'] = row[5]
            d['ishosting'] = row[6]
            d['isresidentialproxy'] = row[7]
            d['iscloudgaming'] = row[8]
            d['isrelay'] = row[9]
            d['risk_score'] = row[10]
            d['risk_level'] = row[11]
            d['date'] = row[2]
            data.append(d)

        return jsonify(data)
    except Exception as e:
        print(f'Error - {e}')
        return jsonify({'error': 'Internal Server Error'}), 500
    finally:
        conn.close()
            

if __name__ == "__main__":
    app.run('0.0.0.0', 8080, debug=True)