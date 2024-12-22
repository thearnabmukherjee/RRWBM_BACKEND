from fastapi import FastAPI, HTTPException, Security, Body, Response, Request, Cookie
from pydantic import BaseModel
from fastapi.responses import RedirectResponse
from typing import List
from urllib.parse import urlencode
from datetime import datetime
import httpx, logging, json
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func
from internal.db import *
from internal.dependencies import *
import routers.role_router
import routers.permission_router
import routers.user_role_router


app = FastAPI()
lstPeriodicTasks = []


app.include_router(routers.role_router.app, prefix='/role', tags=['Roles management'])
app.include_router(routers.permission_router.app, prefix='/permission', tags=['Permission management'])
app.include_router(routers.user_role_router.app, prefix='/user-role', tags=['Role and User management'])


async def _create_default_data():
    #
    #   Create default role if does not exist already
    #
    if await database.execute(auth_group.count()) == 0:
        grp_id = (await database.fetch_one(auth_group.insert().returning(auth_group.c.id).values(role = 'Normal')))['id']
        
        #
        #   Assign all permissions to this role
        #
        _arr_perm = [(e.name, e.value) for e in Permissions]
        dctValues = { 'group_id': grp_id, 'arr_perms': [x[0] for x in _arr_perm] }
        await database.execute(auth_role_perm.insert().values(**dctValues))

#
#   App startup
#
@app.on_event("startup")
async def startup():
    await database.connect()

    #
    #   Start token refresher task
    #
    loop = asyncio.get_event_loop()
    lstPeriodicTasks.append(loop.create_task(periodic_token_refresher()))
    await _create_default_data()

#
#   App shutdown
#
@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    for t in lstPeriodicTasks:
        t.cancel()


#
#   Ping
#
@app.get("/ping")
async def ping(objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    return {}


#
#   Get authentication state
#
@app.get("/valid-state")
async def get_valid_state():
    state = generate_random_string(36)
    valid_till = datetime.now() + timedelta(minutes = 5)
    if (await database.execute(tbl_ValidAuthState.insert().values(state = state, valid_till = valid_till))) > 0:
        return { 'isError': False, 'msg': state }
    else:
        return { 'isError': True, 'msg': 'Failed to get valid auth state' }

#
#   Refresh tokens
#
@app.get("/refresh")
async def get_refresh_token(response: Response, objToken: AuthTokenOut = Depends(dp_get_current_user_from_local_refresh_cookie)):
    #
    #   Generate local access and refresh tokens
    #
    _new_access_token = generate_local_access_token(objToken.username, objToken.id, objToken.roles, objToken.first_name, objToken.last_name)
    _new_refresh_token = generate_local_refresh_token(objToken.username, objToken.id)
    set_login_cookies(response, _new_access_token, _new_refresh_token)

    #
    #   Try to refresh SSO tokens also
    #
    if (await make_tokens_valid(objToken.id)) is not None:
        return { 'isError': False, 'msg': 'Success' }
    else:
        return { 'isError': True, 'msg': 'Failed to load SSO tokens' }

#
#   Logout
#
@app.get("/logout")
async def logout(response: Response, objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    force_logout_user(objToken.id)
    clear_login_cookies(response)
    return {}

#
#   Back channel logout
#
@app.post("/back-channel-logout")
async def back_channel_logout(token: str = Body(..., min_length=1)):
    user_id = validate_external_logout_token(token, MY_CLIENT_ID)
    if user_id > 0:
        row = await database.fetch_one(auth_user.select().where(auth_user.c.sso_id == user_id))
        if row is not None:
            force_logout_user(user_id)
            return { 'res': 'Success' }
    return { 'res': 'Failure' }


#
#   Submit auth code. works as login for user
#
@app.get("/submit-auth-code")
async def submit_auth_code( response: Response, 
                            code: str = Query(..., max_length=100), 
                            state: str = Query(None, max_length=100)):
    #
    #   Check if state is valid
    #
    valid_state_row = await database.fetch_one(tbl_ValidAuthState.select().where(tbl_ValidAuthState.c.state == state))
    if valid_state_row is None:
        return { 'isError': True, 'msg': 'Invalid login state. Please try login again on RRWBM portal' }
    else:
        await database.execute(tbl_ValidAuthState.delete().where(tbl_ValidAuthState.c.id == valid_state_row['id']))
        if valid_state_row['valid_till'] < datetime.now():
            return { 'isError': True, 'msg': 'Invalid login state. Please try login again on RRWBM portal' }

    #
    #   Fetch tokens
    #
    sso_id = -1
    username = ""
    first_name = ""
    last_name = ""
    email = ""
    tokens = dict()
    try:
        async with httpx.AsyncClient(verify=SSO_CERTIFICATE) as client:
            res = await client.post(SSO_TOKEN_URL, json = dict( grant_type = 'authorization_code',
                                                                code = code,
                                                                redirect_uri = SSO_REDIRECT_URI,
                                                                client_id = MY_CLIENT_ID,
                                                                client_secret = MY_CLIENT_SECRET))
            if res.status_code == httpx.codes.OK:
                obj = res.json()
                for _client_id in KNOWN_CLIENT_IDS:
                    #
                    #   Handle external tokens
                    #
                    if _client_id != MY_CLIENT_ID:
                        if _client_id in obj:
                            access_token = obj[_client_id]['access_token']
                            refresh_token = obj[_client_id]['refresh_token']
                            _scope = obj[_client_id]['scope']
                            _id_token = obj[_client_id]['id_token']
                            #
                            #   Validate external access_token
                            #
                            access_token_obj = validate_external_access_token(access_token, _client_id)
                            if access_token_obj is None:
                                return { 'isError': True, 'msg': 'SSO server provided invalid tokens1. Please contact RRWBM administrator' }
                            #
                            #   Validate external refresh_token
                            #
                            refresh_token_obj = validate_external_refresh_token(refresh_token)
                            if refresh_token_obj is None:
                                return { 'isError': True, 'msg': 'SSO server provided invalid tokens2. Please contact RRWBM administrator' }
                            #
                            #   Validate external id_token
                            #
                            id_token_obj = validate_id_token(_id_token, _client_id)
                            if id_token_obj is None:
                                return { 'isError': True, 'msg': 'SSO server provided invalid tokens3. Please contact RRWBM administrator' }
                            tokens[_client_id] = dict(expires_in = obj['expires_in'], 
                                                      access_token = access_token, 
                                                      refresh_token = refresh_token,
                                                      scope = _scope,
                                                      id_token = _id_token,
                                                      issued_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                    #
                    #   Handle own token
                    #
                    elif _client_id == MY_CLIENT_ID:
                        if _client_id in obj:
                            #   Own access and refresh tokens are not required
                            #
                            #   Validate own id_token. Used for SSO
                            #
                            _id_token = obj[_client_id]['id_token']
                            id_token_obj = validate_id_token(_id_token, _client_id)
                            if id_token_obj is None:
                                return { 'isError': True, 'msg': 'SSO server provided invalid tokens4. Please contact RRWBM administrator' }

                            sso_id = id_token_obj['user_id']
                            username = id_token_obj['username']
                            first_name = id_token_obj['first_name']
                            last_name = id_token_obj['last_name']
                            email = id_token_obj['email']

    except Exception as e:
        logging.exception(str(e))
        return { 'isError': True, 'msg': 'Failed to connect to SSO server. Please contact RRWBM administrator' }
    
    if sso_id <= 0:
        return { 'isError': True, 'msg': 'SSO server failed to provide valid user identity. Please contact RRWBM administrator' }
    
    #
    #   Link to database record
    #
    query = (auth_user.c.sso_id == sso_id) & (auth_user.c.username == username)
    row = await database.fetch_one(auth_user.select().where(query))
    if row is None:
        #
        #   New registration
        #
        await database.execute(auth_user.insert().values(sso_id = sso_id, 
                                                         username = username, 
                                                         first_name = first_name,
                                                         last_name = last_name,
                                                         email = email,
                                                         status = None,
                                                         tokens = tokens))
    else:
        #
        #   Update details in database
        #
        await database.execute(auth_user.update().where(query).values(username = username, 
                                                                     first_name = first_name,
                                                                     last_name = last_name,
                                                                     email = email,
                                                                     tokens = tokens))

    row = await database.fetch_one(auth_user.select().where((auth_user.c.sso_id == sso_id) & (auth_user.c.username == username)))
    if row['status'] in ['disabled', 'blocked']:
        return { 'isError': True, 'msg': 'Your account is disabled/blocked' }

    dctRoles = { role['id']: role['role'] for role in await database.fetch_all(auth_group.select()) }
    arrAssignedRoles = list(set([dctRoles[r['group_id']] for r in await database.fetch_all(auth_membership.select().where(auth_membership.c.user_id == row['id']))]))

    access_token = generate_local_access_token(username, row['id'], arrAssignedRoles, first_name, last_name)
    refresh_token = generate_local_refresh_token(username, row['id'])

    set_login_cookies(response, access_token, refresh_token)
    return { 'isError': False, 'msg': 'Logged in successfully' }

#
#   Are tokens valid
#
@app.get("/tokens-valid")
async def are_tokens_valid(objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if (await make_tokens_valid(objToken.id)) is not None:
        return {}
    else:
        raise HTTPException(status_code=401, detail='Failed to refresh tokens')

