import httpx
import re

async def fetch_security_mail(sesja: httpx.AsyncClient) -> str:
    # Gets the security mail from the account
    
    proofs = await sesja.get(
        "https://account.live.com/proofs/manage/additional?mkt=en-US&refd=account.microsoft.com&refp=security",
        headers = {
            "Accept-Language": "en-US,en;q=0.5",
            "Referer": "https://login.live.com/"
        }
    )

    sec_mail = re.search(r'"displayProofName"\s*:\s*"([^"]+)"', proofs.text).group(1)
    return sec_mail.replace(r"\u0040", "@")