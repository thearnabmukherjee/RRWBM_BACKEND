from internal.db import *
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


#
#   Get list of divisions
#
@app.get("/")
async def get_divisions(response: Response,
                        objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.LIST_DIVISIONS):
        raise HTTPException(status_code = 403, detail = "Access denied")
    
    try:
        obj = await take_common_action(response, objToken.id)
        if obj is not None:
            return obj
        
        res = await get_divisions_list(objToken.id)
        if res is None:
            return { 'isError': True, 'msg': 'An error occurred' }
        else:
            return { 'isError': False, 'msg': res }
    except Exception as e:
        print(str(e))
        return { 'isError': True, 'msg': 'An error occurred. Check server logs' }

#
#   Create new division. Admin required
#
@app.post("/")
async def create_new_division(response: Response,
                              abbr: str = Body(..., max_length=512),
                              description: str = Body(..., max_length=512),
                              objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.CREATE_DIVISION):
        raise HTTPException(status_code = 403, detail = "Access denied")
    try:
        obj = await take_common_action(response, objToken.id)
        if obj is not None:
            return obj
        #
        #   Connect with IDS Portal
        #
        row = await database.fetch_one(auth_user.select().where(auth_user.c.id == objToken.id))
        url = "{}/gui/external-divisions".format(IDS_BASE_URL)
        params = { 'id_token': extract_id_token(row['tokens']) }
        access_token = extract_access_token(row['tokens'])

        r = await safe_network_call( url, 
                                    'POST', 
                                    params,
                                    { 'authorization': 'Bearer {}'.format(access_token) },
                                    None, None, 
                                    { 'abbr': abbr, 'description': description }, 
                                    objToken.id, make_tokens_valid, True)
        if r is None:
            return { 'isError': True, 'msg': 'An error occurred' }
        elif r.status_code == httpx.codes.OK:
            obj = r.json()
            return obj

        return { 'isError': True, 'msg': 'An error occurred' }
    except Exception as e:
        print(str(e))
        return { 'isError': True, 'msg': 'An error occurred. Check server logs' }
