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
#   Get list of plants
#
@app.get("/")
async def get_plants(response: Response,
                     objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    can_see_all_plants = await has_permission(objToken.roles, Permissions.LIST_ALL_PLANTS)
    can_see_only_assigned_plants = await has_permission(objToken.roles, Permissions.LIST_ASSIGNED_PLANTS)

    if (not can_see_all_plants) and (not can_see_only_assigned_plants):
        raise HTTPException(status_code = 403, detail = "Access denied")

    try:
        obj = await take_common_action(response, objToken.id)
        if obj is not None:
            return obj

        res = await get_plant_list(objToken.id, None)
        if res is None:
            return { 'isError': True, 'msg': 'An error occurred' }
        else:
            #
            #   Another filter for HP only
            #
            if (not can_see_all_plants) and can_see_only_assigned_plants:
                rows = await database.fetch_all(tbl_HP_Plant_Binding.select().where(tbl_HP_Plant_Binding.c.hp_id == objToken.id))
                lstMyPlantIds = list(set([r['plant_id'] for r in rows]))
                res = [r for r in res if r['id'] in lstMyPlantIds]

            return { 'isError':False, 'msg': res }
    except Exception as e:
        print(str(e))
        return { 'isError': True, 'msg': 'An error occurred. Check server logs' }

#
#   Create new division. Admin required
#
@app.post("/plants")
async def create_new_plant( response: Response,
                            name: str = Body(..., max_length=512),
                            plocation: str = Body(..., max_length=512),
                            is_strategic: bool = Body(...),
                            objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.CREATE_PLANT):
        raise HTTPException(status_code = 403, detail = "Access denied")
    try:
        obj = await take_common_action(response, objToken.id)
        if obj is not None:
            return obj
        #
        #   Connect with IDS Portal
        #
        row = await database.fetch_one(auth_user.select().where(auth_user.c.id == objToken.id))
        url = "{}/gui/external-plants".format(IDS_BASE_URL)
        params = { 'id_token': extract_id_token(row['tokens']) }
        access_token = extract_access_token(row['tokens'])

        #
        #   Make network call
        #
        r = await safe_network_call( url, 
                                    'POST', 
                                    params,
                                    { 'authorization': 'Bearer {}'.format(access_token) },
                                    None, None, 
                                    { 'name': name, 'plocation': plocation, 'is_strategic': is_strategic }, 
                                    objToken.id, make_tokens_valid, True)
        if r is None:
            { 'isError': True, 'msg': 'An error occurred' }
        elif r.status_code == httpx.codes.OK:
            obj = r.json()
            return obj

        return { 'isError': True, 'msg': 'An error occurred' }
    except Exception as e:
        print(str(e))
        return { 'isError': True, 'msg': 'An error occurred. Check server logs' }

