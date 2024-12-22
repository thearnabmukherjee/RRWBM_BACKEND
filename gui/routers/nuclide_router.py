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
from typing import List

app = APIRouter()


def safe_nuclide_name(data: str):
    if data in [None, ""]: return None
    SPACE = string.ascii_letters + string.digits + "-"
    return "".join([c for c in data if c in SPACE])



#
#   Get list of routes
#
@app.get("/")
async def get_records(response: Response,
                      objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.LIST_NUCLIDES):
        raise HTTPException(status_code = 403, detail = "Access denied")
    
    lst = []
    rows = await database.fetch_all(tbl_Radionuclides.select())
    for row in rows:
        dct = dict(row)
        dct['created_on'] = dct['created_on'].strftime('%Y-%m-%d %H:%M:%S')
        lst.append(dct)
    return lst


#
#   Create new intake route
#
@app.post("/")
async def create_record(response: Response,
                        name: str = Body(..., max_length=512, min_length=1, embed=True),
                        mda: float = Body(None, ge=0, le=999999999),
                        arr_energy: List[float] = Body(None, max_items=10),
                        arr_yield: List[float] = Body(None, max_items=10),
                        objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.CREATE_NEW_NUCLIDE):
        raise HTTPException(status_code = 403, detail = "Access denied")
    
    #
    #   Sanitize name
    #
    if safe_nuclide_name(name) != name:
        return { 'isError': True, 'msg': 'Please provide valid nuclide name' }

    #
    #   Check duplicate name
    #   
    q = (tbl_Radionuclides.c.name.ilike(name))
    row = await database.fetch_one(tbl_Radionuclides.select().where(q))
    if row is not None:
        return { 'isError': True, 'msg': 'Specified nuclide already exists' }
    
    #
    #   Check mda
    #
    if mda is not None:
        if mda <= 0:
            return { 'isError': True, 'msg': 'MDA must be greater than zero' }
    
    #
    #   Validate energies
    #
    if arr_energy is not None:
        arr_energy = [e for e in arr_energy if e > 0]
        if len(arr_energy) == 0:
            return { 'isError': True, 'msg': 'Please specify valid energy values' }
    
    #
    #   Validate yields
    #
    if arr_yield is not None:
        arr_yield = [e for e in arr_yield if e >= 0]
        if len(arr_yield) == 0:
            return { 'isError': True, 'msg': 'Please specify valid yield values' }
    
    #
    #   Match energies and yield
    #
    if len(arr_energy) != len(arr_yield):
        return { 'isError': True, 'msg': 'Each energy record must have a matching yield' }


    await database.execute(tbl_Radionuclides.insert().values(name = name, 
                                                             mda = mda,
                                                             arr_energy = arr_energy,
                                                             arr_yield = arr_yield,
                                                             created_on = datetime.now(),
                                                             created_by = objToken.id))
    return { 'isError': False, 'msg': 'Nuclide created successfully' }



#
#   Create new intake route
#
@app.put("/")
async def update_record(response: Response,
                        record_id: int = Body(..., ge=1, le=99999999),
                        mda: float = Body(None, ge=0, le=999999999),
                        arr_energy: List[float] = Body(None, max_items=10),
                        arr_yield: List[float] = Body(None, max_items=10),
                        objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.MODIFY_EXISTING_NUCLIDE):
        raise HTTPException(status_code = 403, detail = "Access denied")
    
    #
    #   Check if record exists
    #
    row = await database.fetch_one(tbl_Radionuclides.select().where(tbl_Radionuclides.c.id == record_id))
    if row is None:
        return { 'isError': True, 'msg': 'Specified record does not exist' }

    
    #
    #   Check mda
    #
    if mda is not None:
        if mda <= 0:
            return { 'isError': True, 'msg': 'MDA must be greater than zero' }
    
    #
    #   Validate energies
    #
    if arr_energy is not None:
        arr_energy = [e for e in arr_energy if e > 0]
        if len(arr_energy) == 0:
            return { 'isError': True, 'msg': 'Please specify valid energy values' }
    
    #
    #   Validate yields
    #
    if arr_yield is not None:
        arr_yield = [e for e in arr_yield if e >= 0]
        if len(arr_yield) == 0:
            return { 'isError': True, 'msg': 'Please specify valid yield values' }
    
    #
    #   Match energies and yield
    #
    if len(arr_energy) != len(arr_yield):
        return { 'isError': True, 'msg': 'Each energy record must have a matching yield' }


    await database.execute(tbl_Radionuclides.update().where(tbl_Radionuclides.c.id == record_id).values(mda = mda,
                                                                                                        arr_energy = arr_energy,
                                                                                                        arr_yield = arr_yield))
    return { 'isError': False, 'msg': 'Nuclide updated successfully' }



