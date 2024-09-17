import json
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from programs import ecc, gen_key, rsa

app = FastAPI(title="A REVIEW OF PUBLIC KEY CRYPTOGRAPHY (DEMO)")


class Message(BaseModel):
    message: str
    public_key: str


@app.get("/")
def home():
    response = {
        "message": "A REVIEW OF PUBLIC KEY CRYPTOGRAPHY",
        "API doc address": "http://127.0.0.1:8000/docs",
    }
    return response


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


from fastapi import WebSocket, WebSocketDisconnect
import json
from Crypto.PublicKey import RSA
from programs import rsa  # Assuming rsa.rsa_encrypt is in the rsa module


@app.websocket("/secured-network")
async def secured_network(socket: WebSocket):
    await socket.accept()
    try:
        while True:
            # Receive and parse the data from the WebSocket
            data = await socket.receive_text()
            data_json = json.loads(data)
            message = data_json["message"]
            public_key_str = data_json["public_key"]

            # Print received data for debugging
            print(f"Message to encrypt: {message}")
            print(f"Public key received: {public_key_str}")

            # Convert the public key from a string with literal \n to a proper PEM format
            public_key_str = public_key_str.replace("\\n", "\n")

            # Convert the public key from string to RSA key object
            try:
                public_key = RSA.import_key(public_key_str)
            except ValueError as e:
                print(f"Failed to import public key: {e}")
                await socket.send_text("Invalid public key format")
                continue

            # Encrypt the message using the RSA public key
            encrypted_message = rsa.rsa_encrypt(message, public_key_str)

            # Send the encrypted message back to the client
            await socket.send_text(
                encrypted_message
            )  # Encrypted message is already in base64 string

    except WebSocketDisconnect:
        print("Client disconnected")


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
