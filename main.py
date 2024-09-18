import json
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from programs import rsa
from Crypto.PublicKey import RSA
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from programs import ecc, gen_key, rsa
from Crypto.PublicKey import RSA

app = FastAPI(title="A REVIEW OF PUBLIC KEY CRYPTOGRAPHY (DEMO)" )

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],  
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],  
)


class Message(BaseModel):
    message: str  # The encrypted message (in base64 format)
    private_key: str  # The private key (in PEM format)


@app.get("/")
def home():
    response = {
        "message": "A REVIEW OF PUBLIC KEY CRYPTOGRAPHY",
        "API doc address": "https://statistical-jennica-emekadefirst-4a88678e.koyeb.app/docs",
    }
    return response


@app.post("/message/decrypt")
def decrypt(message: Message):
    try:
        decrypted_message = rsa.rsa_decrypt(message.message, message.private_key)
        return {"decrypted_message": decrypted_message}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")


@app.get("/rsa/key")
def fetch_rsa_keys():
    key = gen_key.generate_rsa_keys()
    return {
        "message": "RSA Keys generated and saved.",
        "public_key": key["public_key"],
        "private_key": key["private_key"],
    }


@app.get("/ecc/key")
def fetch_ecc_keys():
    key = ecc.generate_ecc_keys()
    return {
        "message": "ECC Keys generated and saved.",
        "public_key": key["public_key"],
        "private_key": key["private_key"],
    }


@app.websocket("/secured-network")
async def secured_network(socket: WebSocket):
    await socket.accept()
    try:
        while True:

            data = await socket.receive_text()
            data_json = json.loads(data)
            message = data_json["message"]
            public_key_str = data_json["public_key"]
            print(f"Message to encrypt: {message}")
            print(f"Public key received: {public_key_str}")

            public_key_str = public_key_str.replace("\\n", "\n")
            try:
                public_key = RSA.import_key(public_key_str)
            except ValueError as e:
                print(f"Failed to import public key: {e}")
                await socket.send_text("Invalid public key format")
                continue
            encrypted_message = rsa.rsa_encrypt(message, public_key_str)


            await socket.send_text(
                encrypted_message
            )  

    except WebSocketDisconnect:
        print("Client disconnected")


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
