from fastapi import FastAPI, HTTPException, Security, Body, Response, Request, Cookie
from pydantic import BaseModel
from fastapi.responses import RedirectResponse
from typing import List
from urllib.parse import urlencode
from datetime import datetime
import httpx, logging, json
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func
from internal.db import *
from internal.dependencies import *
import routers.h10_router


app = FastAPI()

app.include_router(routers.h10_router.app, prefix='/10h', tags=['10H form management'])


#
#   App startup
#
@app.on_event("startup")
async def startup():
    await database.connect()



#
#   App shutdown
#
@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()