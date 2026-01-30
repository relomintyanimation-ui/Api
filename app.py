import threading, time, asyncio, os, json, datetime
from flask import Flask, render_template, jsonify, request
import requests

# 1. Custom Files Import
from xC4 import * # 2. Pb2 Files Import
try:
    from Pb2 import MajoRLoGinrEq_pb2, MajoRLoGinrEs_pb2, PorTs_pb2
except ImportError:
    pass

app = Flask(__name__)

# === APNA ID PASSWORD YAHAN DALEIN ===
MY_UID = "4401213804"
MY_PASS = "132A508CEE1C3F0164A7FCD6754AEEF32EE4384EE6071157D17B40F48667FD58"

# === DASHBOARD DATA ===
BOT_DATA = {
    "status": "STOPPED",
    "logs": [],
    "name": "Unknown",
    "uid": "---",
    "level": 0,
    "xp": 0,
    "next_xp": 100,
    "uptime": "00:00:00"
}

STOP_FLAG = threading.Event()
START_TIME = 0

# === MAIN FUNCTION JO ONLINE RAKHEGA ===
async def bot_loop():
    global START_TIME
    
    # 1. Login Logic
    BOT_DATA["status"] = "CONNECTING"
    BOT_DATA["logs"].append("Logging in...")
    
    # Garena Token request
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 12)', 'Content-Type': 'application/x-www-form-urlencoded', 'X-GA': 'v1 1'}
    data = {"uid": MY_UID, "password": MY_PASS, "client_id": "100067"}
    
    try:
        res = requests.post(url, headers=headers, data=data)
        if res.status_code != 200:
            BOT_DATA["status"] = "ERROR"
            BOT_DATA["logs"].append("Login Failed! Check ID/Pass")
            return
        d = res.json()
        oid, token = d.get("open_id"), d.get("access_token")
    except Exception as e:
        BOT_DATA["status"] = "ERROR"
        BOT_DATA["logs"].append(f"Net Error: {e}")
        return

    # 2. Major Login (Encryption Check)
    BOT_DATA["logs"].append("Connecting to Game Server...")
    mj = MajoRLoGinrEq_pb2.MajorLogin()
    mj.event_time = str(datetime.now())[:-7]
    mj.game_name = "free fire"
    mj.platform_id = 1
    mj.client_version = "1.119.1"
    mj.client_version_code = "2020119001"
    mj.open_id = oid
    mj.access_token = token
    mj.device_type = "Handheld"
    
    try:
        # xC4 Key use karke encrypt kar rahe hain
        pyl = await EnC_AEs(mj.SerializeToString().hex())
        
        # Server ko bhej rahe hain
        mj_url = "https://loginbp.ggblueshark.com/MajorLogin"
        mj_head = {'ReleaseVersion': 'OB52', 'User-Agent': 'Dalvik/2.1.0'}
        mj_res = requests.post(mj_url, data=bytes.fromhex(pyl), headers=mj_head, verify=False)
        
        if mj_res.status_code != 200:
            BOT_DATA["status"] = "ERROR"
            BOT_DATA["logs"].append("MajorLogin Failed (Key Error?)")
            return

        # Response Decrypt kar rahe hain
        dec_hex = await DEc_AEs(mj_res.content.hex())
        resp = MajoRLoGinrEs_pb2.MajorLoginRes()
        resp.ParseFromString(bytes.fromhex(dec_hex))
        
        # Connection Keys mili
        SessionKey = resp.key
        SessionIv = resp.iv
        
    except Exception as e:
        BOT_DATA["status"] = "ERROR"
        BOT_DATA["logs"].append(f"Crypto Error: {e}")
        return

    # 3. ONLINE LOOP (Ye hai wo Main Setup)
    BOT_DATA["status"] = "ACTIVE"
    BOT_DATA["uid"] = str(resp.account_uid)
    BOT_DATA["logs"].append("Bot is ONLINE (Lobby Mode)")
    START_TIME = time.time()
    
    # TCP Connection Setup
    ip, port = "203.117.155.10", 10000
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        
        # Auth Packet bhejo (Login complete karne ke liye)
        # (Yahan hum seedha heartbeat loop start kar rahe hain safe side ke liye)
        
        while not STOP_FLAG.is_set():
            # Uptime Update
            elapsed = int(time.time() - START_TIME)
            m, s = divmod(elapsed, 60)
            h, m = divmod(m, 60)
            BOT_DATA["uptime"] = f"{h:02d}h {m:02d}m {s:02d}s"
            
            # --- YE HAI WO FUNCTION JO ONLINE RAKHEGA ---
            try:
                # Step 1 se HeartBeat function call kiya
                ping_packet = await HeartBeat(SessionKey, SessionIv)
                writer.write(ping_packet)
                await writer.drain()
                
                # Visual Update (Fake XP badhana dikhane ke liye)
                BOT_DATA["xp"] += 1
                
            except Exception as e:
                BOT_DATA["logs"].append(f"Ping Error: {e}")
                break
            
            await asyncio.sleep(20) # Har 20 second mein repeat
            
        writer.close()
        
    except Exception as e:
        BOT_DATA["status"] = "ERROR"
        BOT_DATA["logs"].append(f"Socket Error: {e}")

# === FLASK SERVER SETUP ===
def run_async_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(bot_loop())

@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/status')
def status(): return jsonify(BOT_DATA)

@app.route('/api/start', methods=['POST'])
def start():
    if BOT_DATA["status"] == "ACTIVE": return jsonify({"msg": "Running"})
    STOP_FLAG.clear()
    BOT_DATA["logs"] = []
    t = threading.Thread(target=run_async_loop)
    t.daemon = True
    t.start()
    return jsonify({"msg": "Started"})

@app.route('/api/stop', methods=['POST'])
def stop():
    STOP_FLAG.set()
    BOT_DATA["status"] = "STOPPED"
    return jsonify({"msg": "Stopped"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
