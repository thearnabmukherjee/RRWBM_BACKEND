from internal.db import *
from internal.dependencies import *
from fastapi.responses import StreamingResponse
import logging, os, io, base64
import binascii, string, httpx
from base64 import b16decode, b64decode
from base64 import b16encode
from datetime import datetime
from fastapi import APIRouter, Query, Body
from pydantic import BaseModel, Field
import httpx, logging, string, copy

app = APIRouter()

async def _require_permission(objToken, perm: Permissions):
    if not await has_permission(objToken.roles, perm):
        raise HTTPException(status_code = 403, detail = "Access denied")



#
#   List of 10H forms
#
@app.get("/")
async def get_list_forms(objToken = Depends(dp_get_current_user_from_cookie)):
    await _require_permission(objToken, Permissions.LIST_PERMISSIONS)
    