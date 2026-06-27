import uvicorn
import os

if __name__ == "__main__":
    # Get port from environment or default to 8000
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    
    print(f"Starting APK Sentinel AI Backend on {host}:{port}...")
    uvicorn.run("app.main:app", host=host, port=port, reload=True)
