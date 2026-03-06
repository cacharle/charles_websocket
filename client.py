import asyncio
import websockets

async def dump_client(uri):
    async with websockets.connect(uri) as websocket:
        print(f"Connected to {uri}")

        async def receive():
            while True:
                try:
                    message = await websocket.recv()
                    print(f"Received: {message}")
                except websockets.ConnectionClosed:
                    print("Connection closed")
                    break

        async def send():
            while True:
                msg = input("Send: ")
                if msg.lower() == "exit":
                    await websocket.close()
                    break
                await websocket.send(msg)

        await asyncio.gather(receive(), send())

if __name__ == "__main__":
    uri = "ws://localhost:8080"
    asyncio.run(dump_client(uri))
