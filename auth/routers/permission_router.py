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
#   List of permissions
#
@app.get("/")
async def get_permissions(objToken = Depends(dp_get_current_user_from_cookie)):
    await _require_permission(objToken, Permissions.LIST_PERMISSIONS)
    return get_all_permissions()

#
#   Assign permission to a role
#
@database.transaction()
@app.put("/")
async def assign_perm_role( role_id: int = Body(..., ge=1),
                            arrPerm: List[Permissions] = Body(..., min_items=0, max_items=1000),
                            objToken = Depends(dp_get_current_user_from_cookie)):
    await _require_permission(objToken, Permissions.ASSIGN_PERMISSIONS)

    #
    #   Check valid role
    #
    row = await database.fetch_one(auth_group.select().where(auth_group.c.id == role_id))
    if row is None:
        return { 'isError': True, 'msg': 'Specified role does not exist' }
    
    arr = list(set([r.name for r in arrPerm]))

    #
    #   Update database
    #
    await database.execute(auth_role_perm.delete().where(auth_role_perm.c.group_id == role_id))
    await database.execute(auth_role_perm.insert().values(group_id = role_id,
                                                          arr_perms = arr))
    #
    #   Global logout
    #
    blacklist_global_access_token()
    return { 'isError': False, 'msg': 'Permissions changed for the role successfully' }

#
#   Get permissions assigned to each role
#
@app.get("/role-permissions")
async def get_role_permissions(objToken = Depends(dp_get_current_user_from_cookie)):
    await _require_permission(objToken, Permissions.VIEW_PERMISSION_ROLE_ASSIGNMENT)
    rows = await database.fetch_all(auth_role_perm.select())
    return [dict(r) for r in rows]
