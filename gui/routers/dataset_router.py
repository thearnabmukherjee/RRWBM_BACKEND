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


def safe_datatset_name(data: str):
    if data in [None, ""]: return None
    SPACE = string.ascii_letters + string.digits + "-_"
    return "".join([c for c in data if c in SPACE])



#
#   Get list of dataset
#
@app.get("/")
async def get_records(response: Response,
                      objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.LIST_DATASETS):
        raise HTTPException(status_code = 403, detail = "Access denied")
    
    lst = []
    rows = await database.fetch_all(tbl_DataSet.select())
    for row in rows:
        dct = dict(row)
        dct['created_on'] = dct['created_on'].strftime('%Y-%m-%d %H:%M:%S')
        lst.append(dct)
    return lst


#
#   Create new dataset
#
@app.post("/")
async def create_record(response: Response,
                        name: str = Body(..., max_length=512, min_length=1, embed=True),
                        objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.CREATE_NEW_DATASET):
        raise HTTPException(status_code = 403, detail = "Access denied")
    
    if safe_datatset_name(name) != name:
        return { 'isError': True, 'msg': 'Please provide valid dataset name' }

    q = (tbl_DataSet.c.name.ilike(name))
    row = await database.fetch_one(tbl_DataSet.select().where(q))
    if row is not None:
        return { 'isError': True, 'msg': 'Specified dataset already exists' }
    
    await database.execute(tbl_DataSet.insert().values( name = name, 
                                                        created_on = datetime.now(),
                                                        created_by = objToken.id))
    return { 'isError': False, 'msg': 'Dataset created successfully' }

