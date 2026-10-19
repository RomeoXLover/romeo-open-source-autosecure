import httpx

async def kick_sessions(sesja: httpx.AsyncClient, canary: str):
    # Logout of all devices
    
    remove = await sesja.post(
        "https://account.live.com/API/Proofs/DeleteDevices",
        headers = {
            "canary": canary
        },
        json = {
            "uiflvr": 1001,
            "uaid": "abd2ca2a346c43c198c9ca7e4255f3bc",
            "scid": 100109,
            "hpgid": 201030
        },
        follow_redirects = False
    )
    
    if remove.status_code == 200:
        print("[+] - Sucessfully Logout all devices")
    else:
        print("[X] - Failed to logout of all devices")
