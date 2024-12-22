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

def get_all_permissions():
    return [{ 'code': e.name, 'desc': e.value } for e in Permissions]


#
#   List of registered users
#
@app.get("/only-users")
async def get_users(objToken = Depends(dp_get_current_user_from_cookie)):
    await _require_permission(objToken, Permissions.LIST_USERS)
    rows = await database.fetch_all(auth_user.select().order_by(auth_user.c.username))
    lst = []
    for row in rows:
        dct = dict(row)
        del dct['sso_id']
        del dct['tokens']
        lst.append(dct)
    return lst

#
#   List of role and user assignments
#
@app.get("/")
async def get_user_roles(objToken = Depends(dp_get_current_user_from_cookie)):
    await _require_permission(objToken, Permissions.LIST_USERS_WITH_ROLES)
    rows = await database.fetch_all(auth_membership.select())
    return [dict(r) for r in rows]

#
#   Enable disable user
#
@app.put("/")
async def enable_disable_user(  user_id: int = Body(..., ge=1),
                                is_enable: bool = Body(...),
                                objToken = Depends(dp_get_current_user_from_cookie)):
    await _require_permission(objToken, Permissions.BLOCK_UNBLOCK_USER_ACCOUNT)
    if user_id == objToken.id:
        return { 'isError': True, 'msg': 'You can not operate on yourself' }
    
    row = await database.fetch_one(auth_user.select().where(auth_user.c.id == user_id))
    if row is None:
        return { 'isError': True, 'msg': 'Specified user does not exist' }
    
    if row['status'] in [None, ""] and is_enable:
        return { 'isError': True, 'msg': 'User is already enabled' }
    if row['status'] in ["blocked", "disabled"] and not is_enable:
        return { 'isError': True, 'msg': 'User is already disabled' }

    await database.execute(auth_user.update().where(auth_user.c.id == user_id).values(status = None if is_enable else 'blocked'))
    blacklist_user_access_token(user_id)
    return { 'isError': False, 'msg': 'User {} successfully'.format('enabled' if is_enable else 'disabled') }

#
#   Get my information
#
@app.get("/my-info")
async def get_my_info(objToken = Depends(dp_get_current_user_from_cookie)):
    dct = objToken.dict()
    lstPerm = set()

    #
    #   Find role ids
    #
    grp_rows = await database.fetch_all(auth_group.select())
    dctRoles = { r['role']: r['id'] for r in grp_rows}
    lst_role_ids = [dctRoles[r] for r in objToken.roles]

    #
    #   Find permissions for each role
    #
    rows = await database.fetch_all(auth_role_perm.select().where(auth_role_perm.c.group_id.in_(lst_role_ids)))
    for r in rows:
        lstPerm = lstPerm | r['arr_perms']

    dct['permissions'] = list(lstPerm)
    return dct