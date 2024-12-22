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


def safe_class_name(data: str):
    if data in [None, ""]: return None
    SPACE = string.ascii_letters + string.digits + "-_"
    return "".join([c for c in data if c in SPACE])



#
#   Get list of classes
#
@app.get("/")
async def get_records(response: Response,
                      objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.LIST_CLASS):
        raise HTTPException(status_code = 403, detail = "Access denied")
    
    lst = []
    rows = await database.fetch_all(tbl_Classes.select())
    for row in rows:
        dct = dict(row)
        dct['created_on'] = dct['created_on'].strftime('%Y-%m-%d %H:%M:%S')
        lst.append(dct)
    return lst


#
#   Create new class
#
@app.post("/")
async def create_record(response: Response,
                        name: str = Body(..., max_length=512, min_length=1, embed=True),
                        is_active: bool = Body(...),
                        objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.CREATE_NEW_CLASS):
        raise HTTPException(status_code = 403, detail = "Access denied")
    
    if safe_class_name(name) != name:
        return { 'isError': True, 'msg': 'Please provide valid class name' }

    q = (tbl_Classes.c.name.ilike(name))
    row = await database.fetch_one(tbl_Classes.select().where(q))
    if row is not None:
        return { 'isError': True, 'msg': 'Specified class already exists' }
    
    await database.execute(tbl_Classes.insert().values( name = name,
                                                        is_active = is_active, 
                                                        created_on = datetime.now(),
                                                        created_by = objToken.id))
    return { 'isError': False, 'msg': 'Class created successfully' }

#
#   Enable disable existing class
#
@app.put("/")
async def modify_record(response: Response,
                        record_id: int = Body(..., ge=1, le=99999),
                        is_active: bool = Body(...),
                        objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.ENABLE_DISABLE_CLASS):
        raise HTTPException(status_code = 403, detail = "Access denied")
    
    row = await database.fetch_one(tbl_Classes.select().where(tbl_Classes.c.id == record_id))
    if row is None:
        return { 'isError': True, 'msg': 'Specified class does not exist' }
    
    await database.execute(tbl_Classes.update().where(tbl_Classes.c.id == record_id).values(is_active = is_active))
    return { 'isError': False, 'msg': 'success' }