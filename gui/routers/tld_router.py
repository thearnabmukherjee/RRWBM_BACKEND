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
#   Get list of TLDs
#
@app.get("/")
async def get_tlds(response: Response,
                   objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    can_see_all_tlds = await has_permission(objToken.roles, Permissions.LIST_ALL_TLDS)
    can_see_assigned_tlds = await has_permission(objToken.roles, Permissions.LIST_ASSIGNED_TLDS)
    if (not can_see_all_tlds) and (not can_see_assigned_tlds):
        raise HTTPException(status_code = 403, detail = "Access denied")

    try:
        obj = await take_common_action(response, objToken.id)
        if obj is not None:
            return obj

        res = await get_tld_list(objToken.id, None)
        if res is None:
            return { 'isError': True, 'msg': 'An error occurred' }
        else:
            #
            #   Another filter for HP only
            #
            if (not can_see_all_tlds) and can_see_assigned_tlds:
                rows = await database.fetch_all(tbl_HP_Plant_Binding.select().where(tbl_HP_Plant_Binding.c.hp_id == objToken.id))
                lstMyPlantIds = list(set([r['plant_id'] for r in rows]))
                res = [r for r in res if r['plant'] in lstMyPlantIds]
                
            return { 'isError':False, 'msg': res }
    except Exception as e:
        print(str(e))
        return { 'isError': True, 'msg': 'An error occurred. Check server logs' }

#
#   Create new TLD number
#
@app.post("/")
async def create_new_tld(response: Response,
                         tld: str = Body(..., max_length=10, min_length=1),
                         plant_id: int = Body(..., ge=1),
                         objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.CREATE_TLD):
        raise HTTPException(status_code = 403, detail = "Access denied")

    try:
        obj = await take_common_action(response, objToken.id)
        if obj is not None:
            return obj
        #
        #   Connect with IDS Portal
        #
        row = await database.fetch_one(auth_user.select().where(auth_user.c.id == objToken.id))
        url = "{}/gui/external-tlds".format(IDS_BASE_URL)
        params = { 'id_token': extract_id_token(row['tokens']), 'tld': tld, 'plant_id': plant_id }
        auth_token = extract_access_token(row['tokens'])

        #
        #   Make network call
        #
        r = await safe_network_call( url, 
                                    'POST', 
                                    params,
                                    { 'authorization': 'Bearer {}'.format(auth_token) },
                                    None, None, 
                                    { 'tld': tld, 'plant_id': plant_id }, 
                                    objToken.id, make_tokens_valid, True)
        if r is not None:
            if r.status_code == httpx.codes.OK:
                obj = r.json()
                return obj
            elif r.status_code == 403:
                return { 'isError': True, 'msg': 'You do not have enough rights to create new TLD' }
            else:
                return { 'isError': True, 'msg': 'An error occurred while creating TLDs. Please check IDS Portal server logs. Error code: {}'.format(r.status_code) }

        return { 'isError': True, 'msg': 'An error occurred while creating TLDs. Please check IDS Portal server logs' }
    except Exception as e:
        print(str(e))
        return { 'isError': True, 'msg': 'An error occurred. Check server logs' }

#
#   Change TLD assignment. Admin required
#
@app.put("/")
async def change_tld_assignment(response: Response,
                                tld_ids: List[int] = Body(...),
                                plant_id: int = Body(..., ge=1),
                                objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.CHANGE_TLD_PLANT_BINDING):
        raise HTTPException(status_code = 403, detail = "Access denied")

    try:
        obj = await take_common_action(response, objToken.id)
        if obj is not None:
            return obj
        #
        #   Connect with IDS Portal
        #
        row = await database.fetch_one(auth_user.select().where(auth_user.c.id == objToken.id))
        url = "{}/gui/external-tlds".format(IDS_BASE_URL)
        params = { 'id_token': extract_id_token(row['tokens']) }
        auth_token = extract_access_token(row['tokens'])
        data = { 'tld_ids': tld_ids, 'plant_id': plant_id }

        #
        #   Make network call
        #
        r = await safe_network_call( url, 
                                    'PUT', 
                                    params,
                                    { 'authorization': 'Bearer {}'.format(auth_token) },
                                    None, None, data, 
                                    objToken.id, make_tokens_valid, True)
        if r is not None:
            if r.status_code == httpx.codes.OK:
                obj = r.json()
                return obj
            elif r.status_code == 403:
                return { 'isError': True, 'msg': 'You do not have enough rights on IDS Portal. Access denied' }
            elif r.status_code == 401:
                return { 'isError': True, 'msg': 'You have not given enough permissions to Bioassay portal to assign TLD' }

        return { 'isError': True, 'msg': 'An error occurred' }
    except Exception as e:
        print(str(e))
        return { 'isError': True, 'msg': 'An error occurred. Check server logs' }