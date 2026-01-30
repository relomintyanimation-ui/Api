import requests, os, sys, json, time, urllib3, datetime, socket, threading, ssl, asyncio, aiohttp
from xC4 import *

# === IMPORTING FROM YOUR PB2 FOLDER (IMAGE 2) ===
try:
    # Ye wahi files hain jo tumhare screenshot mein hain
    from Pb2 import MajoRLoGinrEq_pb2   # Screenshot mein hai
    from Pb2 import MajoRLoGinrEs_pb2   # Screenshot mein hai
    from Pb2 import PorTs_pb2           # Screenshot mein hai
    from Pb2 import sQ_pb2              # Screenshot mein hai
except ImportError as e:
    print(f"Error: Pb2 Folder ki files load nahi ho rahi. {e}")
    sys.exit()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# === APNA ID PASSWORD DALO ===
MY_UID = "123456789"
MY_PASS = "PASSWORD_HERE"

# OB52 HEADERS
Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 12; SM-G991B Build/SP1A.210812.016)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'X-Unity-Version': "2020.3.36f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB52"
}

async def encrypted_proto(encoded_hex):
    # xC4 se key leta hai
    return await EnC_AEs(encoded_hex.hex()) 

async def GeNeRaTeAccEss(uid, password):
    # Garena Login API
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    data = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_id": "100067"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=Hr, data=data) as response:
                if response.status != 200: return None, None
                d = await response.json()
                return d.get("open_id"), d.get("access_token")
    except: return None, None

async def EncRypTMajoRLoGin(open_id, access_token):
    # Protobuf Structure create kar raha hai
    mj = MajoRLoGinrEq_pb2.MajorLogin()
    mj.event_time = str(datetime.now())[:-7]
    mj.game_name = "free fire"
    mj.platform_id = 1
    mj.client_version = "1.119.1"
    mj.client_version_code = "2020119001"
    mj.system_software = "Android OS 12 / API-31"
    mj.system_hardware = "Handheld"
    mj.open_id = open_id
    mj.access_token = access_token
    mj.device_type = "Handheld"
    return await EnC_AEs(mj.SerializeToString().hex())

async def MajorLogin(payload):
    if not payload: return None
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    try:
        ssl_ctx = ssl.create_default_context(); ssl_ctx.check_hostname=False; ssl_ctx.verify_mode=ssl.CERT_NONE
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=bytes.fromhex(payload), headers=Hr, ssl=ssl_ctx) as response:
                return await response.read() if response.status == 200 else None
    except: return None

async def TcPOnLine(ip, port, key, iv, AutHToKen):
    print(f" [•] Connecting to Game Server {ip}:{port}...")
    while True:
        try:
            reader, writer = await asyncio.open_connection(ip, int(port))
            writer.write(bytes.fromhex(AutHToKen))
            await writer.drain()
            print(" [✓] Connected! Bot Online.")
            
            while True:
                try:
                    # Heartbeat bhej raha hai (Image 1 mein jo 'Active' dikhana hai)
                    ping = await HeartBeat(key, iv)
                    writer.write(ping)
                    await writer.drain()
                    print(f" [PING] Alive at {datetime.now().strftime('%H:%M:%S')}")
                    
                    try:
                        data = await asyncio.wait_for(reader.read(4096), timeout=25.0)
                        if not data: break
                    except asyncio.TimeoutError: pass
                    await asyncio.sleep(20)
                except: break
            writer.close()
        except Exception as e:
            print(f" [!] Disconnected: {e}")
            await asyncio.sleep(5)

async def MaiiiinE():
    os.system('clear')
    print("--- OB52 BOT SETUP ---")
    
    # 1. Login
    oid, token = await GeNeRaTeAccEss(MY_UID, MY_PASS)
    if not oid: print(" [X] Login Failed!"); return
    print(f" [✓] Login Success: {oid}")

    # 2. Major Login
    pyl = await EncRypTMajoRLoGin(oid, token)
    res = await MajorLogin(pyl)
    if not res: 
        print(" [X] MajorLogin Failed.")
        print(" [!] CAUSE: xC4.py mein 'Key' aur 'Iv' galat/purani hain.")
        return

    # 3. Connect TCP
    # (Yahan hum assume kar rahe hain ki response decrypt ho gaya)
    try:
        dec_res = await DEc_AEs(res.hex()) 
        if not dec_res: raise Exception("Decryption Failed")
        
        # Pb2 file se response read karo
        MjAuth = MajoRLoGinrEs_pb2.MajorLoginRes()
        MjAuth.ParseFromString(bytes.fromhex(dec_res))
        
        # Nayi dynamic keys server se mili
        DynKey, DynIv = MjAuth.key, MjAuth.iv
        TargetID = MjAuth.account_uid
        
        # Auth Packet Generate
        # (Iske liye xC4 mein xAuThSTarTuP function chahiye jo pichle codes mein tha)
        # Simplified connection attempt:
        await TcPOnLine("203.117.155.10", "10000", DynKey, DynIv, "00")
        
    except Exception as e:
        print(f" [X] Error: {e}")
        print(" [!] Key galat hone se data decrypt nahi hua.")

if __name__ == '__main__':
    asyncio.run(MaiiiinE())
