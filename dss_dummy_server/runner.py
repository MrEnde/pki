from fastapi import FastAPI
from dss_dummy_server.endpoints import sign, upload


endpoint = sign.SigningEndpoint()

application = FastAPI()

application.include_router(endpoint.router)
application.include_router(upload.router)
