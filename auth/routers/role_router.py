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
#   Get all roles
#
@app.get("/")
async def get_roles(objToken = Depends(dp_get_current_user_from_cookie)):
    await _require_permission(objToken, Permissions.LIST_ROLES)
    rows = await database.fetch_all(auth_group.select().order_by(auth_group.c.role))
    return [dict(row) for row in rows]

#
#   Create new role
#
@app.post("/")
async def create_role(  role: str = Body(..., min_length=1, max_length=300, embed=True),
                        objToken = Depends(dp_get_current_user_from_cookie)):
    await _require_permission(objToken, Permissions.CREATE_NEW_ROLE)

    #
    #   Validate role contents
    #
    if len([r for r in role if r not in string.ascii_letters + string.digits + " "]) > 0:
        return { 'isError': True, 'msg': 'Role can only contain letters, digits and spaces' }

    #
    #   Check duplicate role
    #
    row  = await database.fetch_one(auth_group.select().where(auth_group.c.role.ilike(role)))
    if row is not None:
        return { 'isError': True, 'msg': 'Specified role already exists' }
    else:
        await database.execute(auth_group.insert().values(role = role))
        return { 'isError': False, 'msg': 'Role created successfully' }

#
#   Change role of the user
#
@database.transaction()
@app.put("/")
async def change_role_of_user(  user_id: int = Body(..., ge=1), 
                                arrRoles: List[int] = Body(..., max_items=1000), 
                                objToken = Depends(dp_get_current_user_from_cookie)):
    await _require_permission(objToken, Permissions.ASSIGN_ROLES)

    #
    #   Validate user
    #
    user_row = await database.fetch_one(auth_user.select().where(auth_user.c.id == user_id))
    if user_row is None:
        return { 'isError': True, 'msg': 'Specified user does not exist' }
    
    #
    #   Validate roles
    #
    if len(arrRoles) > 0:
        arrValidRoleIds = list(set([row['id'] for row in await database.fetch_all(auth_group.select())]))
        if not set(arrRoles).issubset(set(arrValidRoleIds)):
            return { 'isError': True, 'msg': 'Invalid role specified or role no longer exists' }
    
    #
    #   Assign role to user
    #
    await database.execute(auth_membership.delete().where(auth_membership.c.user_id == user_id))
    if len(arrRoles) > 0:
        await database.execute(auth_membership.insert().values( [dict(group_id = role_id, user_id = user_id) for role_id in arrRoles] ))

    #
    #   Forcefully expire user access token
    #
    blacklist_user_access_token(user_id)
    return { 'isError': False, 'msg': 'Roles assigned to the specified user changed successfully' }

#
#   Delete a role
#
@database.transaction()
@app.delete("/")
async def remove_role(  role_id: int = Query(..., ge=1),
                        objToken = Depends(dp_get_current_user_from_cookie)):
    await _require_permission(objToken, Permissions.DELETE_EXISTING_ROLE)

    #
    #   Role exists?
    #
    row = await database.fetch_one(auth_group.select().where(auth_group.c.id == role_id))
    if row is None:
        return { 'isError': True, 'msg': 'Specified role does not exist' }
    
    #
    #   Delete all relevant data
    #
    await database.execute(auth_role_perm.delete().where(auth_role_perm.c.group_id == role_id))
    await database.execute(auth_membership.delete().where(auth_membership.c.group_id == role_id))
    await database.execute(auth_group.delete().where(auth_group.c.id == role_id))

    blacklist_global_access_token()
    return { 'isError': False, 'msg': 'Role deleted successfully' }