from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from jose import JWTError,jwt
import os
from dotenv import load_dotenv
from pydantic import BaseModel
load_dotenv()

class MediaMTXAuthRequest(BaseModel):
    ip: str | None
    user: str | None
    password: str | None
    token: str 
    action: str
    path: str
    
# JWT config
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

ADMIN_USER = os.getenv("ADMIN_USERNAME")
ADMIN_PASS = os.getenv("ADMIN_PASSWORD")

app = FastAPI()

fake_user_db = {
    ADMIN_USER:{"username": ADMIN_USER, "password": ADMIN_PASS}
}


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise JWTError()
        return username
    except JWTError:
        raise HTTPException(status_code=401)


# 製作token
def create_token(username: str):
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data = {"sub": username, "exp": expire}
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


# 登入路由
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_user_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤")
    token = create_token(form_data.username)
    return {"access_token": token, "token_type": "bearer"}

# get userinfo
@app.get("/userinfo")
async def get_userinfo(token: str = Depends(oauth2_scheme)):
    return {"username": decode_access_token(token)}

# 驗證mediaMtxtoken
@app.post("/mediamtx/auth")
async def mediamtx_verify(data: MediaMTXAuthRequest):
    decode_access_token(data.token)
    return {"status":"ok"}


app.mount("/", StaticFiles(directory="static", html=True))