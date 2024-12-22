from db_common import *
from fastapi import Response, HTTPException
from datetime import datetime, timezone
import asyncio, copy, hashlib
from fastapi import Body, Cookie
from sqlalchemy import (Column, Integer, MetaData, String, Table, Text, Boolean, create_engine, ARRAY, DateTime, ForeignKey)
from databases import Database
import sys, os, json, bcrypt, string, logging
from datetime import datetime, timedelta
import jwt as pyjwt
from jose import jwt
from typing import List
import httpx, math, logging
from statistics import mean



_lst_next_token_refresh = []

#################################################   Token generation    #################################################
#################################################                       #################################################
#
#
#   Generate LOCAL access token
#
def generate_local_access_token(username: str, userId: int, roles: List[str], first_name, last_name):
    dt = datetime.now(timezone.utc)
    future_date = dt + timedelta(minutes = LOCAL_TOKEN_EXPIRE_MINUTES)
    payload = dict( iat = dt, 
                    exp = future_date, 
                    iss = ISSUER, 
                    aud = ISSUER,
                    username = username,
                    first_name = first_name,
                    last_name = last_name,
                    ttype = 'ACCESS',
                    id = userId,
                    roles = roles,
                    micro_iat = dt.timestamp())
    token = jwt.encode(payload, LOCAL_TOKEN_SECRET, algorithm = ALGORITHM)
    return token


#
#   Generate LOCAL refresh token
#
def generate_local_refresh_token(username: str, userId: int):
    dt = datetime.now(timezone.utc)
    future_date = dt + timedelta(minutes = LOCAL_REFRESH_TOKEN_EXPIRE_MINUTES)
    payload = dict( iat = dt, 
                    exp = future_date, 
                    iss = ISSUER,
                    ttype = 'REFRESH',
                    aud = ISSUER,
                    id = userId,
                    username = username,
                    micro_iat = dt.timestamp())
    token = jwt.encode(payload, LOCAL_TOKEN_SECRET, algorithm = ALGORITHM)
    return token


#################################################   Token validation    #################################################
#################################################                       #################################################
#
#
#   Validate LOCAL access token
#
def validate_local_access_token(access_token: str):
    try:
        token = jwt.decode(access_token, LOCAL_TOKEN_SECRET, algorithms=[ALGORITHM], issuer=ISSUER, audience = ISSUER)
        #
        #   Check required fields
        #
        requiredFields = ['id', 'username', 'first_name', 'last_name', 'ttype', 'roles', 'aud', 'micro_iat']
        for f in requiredFields:
            if f not in token:
                return None
        if token['ttype'] != 'ACCESS':
            return None
        
        #
        #   Check if token is blacklisted
        #
        try:
            issued_at = datetime.fromtimestamp(token['micro_iat'])

            #
            #   Check local backlist
            #
            obj = redis_db.get("LAT_valid_after_{}".format(token['id']))
            if obj is not None:
                not_valid_before = datetime.fromtimestamp(float(obj))
                if issued_at < not_valid_before:
                    return None
        except Exception as e:
            print('Redis error <dependencies::validate_local_access_token> -> ' + str(e))
        
        #
        #   Check if role is valid
        #
        if token['roles'] is None or (not isinstance(token['roles'], list)):
            return None
        # for r in token['roles']:
        #     if r not in [e.value for e in Role]:
        #         return None
        return token
    except Exception as e:
        print(str(e))
        return None

#
#   Validate LOCAL refresh token
#
def validate_local_refresh_token(refresh_token: str):
    try:
        token = jwt.decode(refresh_token, LOCAL_TOKEN_SECRET, algorithms=[ALGORITHM], issuer=ISSUER, audience=ISSUER)

        #
        #   Check required fields
        #
        requiredFields = ['username', 'ttype', 'id', 'aud', 'micro_iat']
        for f in requiredFields:
            if f not in token:
                return None
        if token['ttype'] != 'REFRESH':
            return None
        
        #
        #   Check if token is blacklisted
        #
        try:
            issued_at = datetime.fromtimestamp(token['micro_iat'])
            obj = redis_db.get("LRT_valid_after_{}".format(token['id']))
            if obj is not None:
                not_valid_before = datetime.fromtimestamp(float(obj))
                if issued_at < not_valid_before:
                    return None
        except Exception as e:
            print('Redis error <dependencies::validate_local_refresh_token> -> ' + str(e))

        return token
    except:
        return None

#
#   Validate EXTERNAL access token   
#
def validate_external_access_token(access_token: str, target_client_id: str):
    try:
        token = pyjwt.decode(access_token, EXTERNAL_PUBLIC_KEY, algorithms=[EXTERNAL_ALGORITHM], issuer=SSO_ISSUER, audience=target_client_id)
        requiredFields = ['aud', 'ttype', 'sub', 'scope']
        for f in requiredFields:
            if f not in token:
                return None
        if token['ttype'] != 'ACCESS':
            return None
        return { 'id': token['sub'], 'scope': token['scope'], 'client_id': token['aud'] }
    except Exception as e:
        print(str(e))
        return None

#
#   Validate EXTERNAL refresh token
#
def validate_external_refresh_token(refresh_token: str):
    try:
        token = pyjwt.decode(refresh_token, EXTERNAL_PUBLIC_KEY, algorithms=[EXTERNAL_ALGORITHM], issuer=SSO_ISSUER, audience=SSO_ISSUER)
        requiredFields = ['aud', 'ttype', 'sub', 'scope', 'user_id']
        for f in requiredFields:
            if f not in token:
                return None
        if token['ttype'] != 'REFRESH':
            return None
        return token
    except Exception as e:
        # print(str(e))
        return None

#
#   Validate EXTERNAL logout token
#
def validate_external_logout_token(token: str, target_client_id: str):
    try:
        token = pyjwt.decode(token, EXTERNAL_PUBLIC_KEY, algorithms=[EXTERNAL_ALGORITHM], issuer=SSO_ISSUER, audience=target_client_id)
        requiredFields = ['aud', 'ttype', 'sub', 'events']
        for f in requiredFields:
            if f not in token:
                return -1
        if token['ttype'] != 'LOGOUT-TOKEN':
            return -1
        
        if (len(token['events']) != 1) or ('http://schemas.openid.net/event/backchannel-logout' not in token['events']) or (len(token['events']['http://schemas.openid.net/event/backchannel-logout']) != 0):
            return -1
        return token['sub']
    except Exception as e:
        return -1

#
#   Validate external Id token
#
def validate_id_token(id_token: str, target_client_id: str):
    try:
        token = pyjwt.decode(id_token, EXTERNAL_PUBLIC_KEY, algorithms=[EXTERNAL_ALGORITHM], issuer=SSO_ISSUER, audience=target_client_id)
        requiredFields = ['aud', 'ttype', 'user_id', 'email', 'username', 'first_name', 'last_name']
        for f in requiredFields:
            if f not in token:
                return None
        if token['ttype'] != 'ID':
            return None
        return token
    except Exception as e:
        return None


#################################################       Dependencies    #################################################
#################################################                       #################################################
#

#
#   Local access token to user
#
def _local_access_token_to_user(access_token: str):
    global _lst_next_token_refresh
    
    if access_token in [None, ""]:
        raise HTTPException(status_code=401, detail='Invalid or expired token')
    obj = validate_local_access_token(access_token)
    if obj is None:
        raise HTTPException(status_code=401, detail='Invalid or expired token')

    #
    #   Register for token refresh
    #
    if obj['id'] not in _lst_next_token_refresh:
        _lst_next_token_refresh.append(obj['id'])

    return AuthTokenOut(id = obj['id'], 
                        username = obj['username'], 
                        first_name = obj['first_name'], 
                        last_name = obj['last_name'], 
                        roles = obj['roles'])

#
#   Local refresh token to user details
#
async def _local_refresh_token_to_user(refresh_token: str):
    obj = validate_local_refresh_token(refresh_token)
    if obj is None:
        raise HTTPException(status_code=401, detail='Invalid or expired token')

    row = await database.fetch_one(auth_user.select().where(auth_user.c.id == obj['id']))
    if row is None:
        raise HTTPException(status_code=401, detail='Invalid or expired token')
    if row['status'] not in [None, ""]:
        raise HTTPException(status_code=403, detail='Access denied')
    
    group_rows = { r['id']: r['role'] for r in await database.fetch_all(auth_group.select()) }
    mem_rows = await database.fetch_all(auth_membership.select().where(auth_membership.c.user_id == row['id']))
    roles = list(set([group_rows[r['group_id']] for r in mem_rows]))

    return AuthTokenOut(id = row['id'], 
                        username = row['username'], 
                        first_name = row['first_name'], 
                        last_name = row['last_name'], 
                        roles = roles)

#
#   Get user by access token from cookie
#
def dp_get_current_user_from_cookie(access_token: str = Cookie(None)):
    return _local_access_token_to_user(access_token)

# #
# #   Get superuser by access token from cookie
# #
# def dp_get_super_user_from_cookie(obj: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
#     if Role.ADMIN.value in obj.roles:
#         return obj
#     else:
#         raise HTTPException(status_code=403, detail='Access denied')

# #
# #   Get HP by access token from cookie
# #
# def dp_get_hp_from_cookie(obj: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
#     if Role.HP.value in obj.roles:
#         return obj
#     else:
#         raise HTTPException(status_code=403, detail='Access denied')

#
#   Get user by access token from header
#
def dp_get_current_user_from_header(authorization: str = Header(...)):
    if authorization.startswith('Bearer '):
        authorization = authorization.replace('Bearer ', '')
    return _local_access_token_to_user(authorization)

#
#   Get user by access token from query
#
def dp_get_current_user_from_query(access_token: str = Query(...)):
    return _local_access_token_to_user(access_token)

#
#   Get consent dictionary from query
#
def dp_get_consent_from_query(token: str = Query(...)):
    obj = validate_local_consent_token(token)
    if obj is None:
        raise HTTPException(status_code=401, detail='Invalid or expired consent')
    return obj

#
#   Get user details from refresh token
#
async def dp_get_current_user_from_local_refresh_cookie(refresh_token: str = Cookie(...)):
    return await _local_refresh_token_to_user(refresh_token)



#
#   Use refresh token to get new access tokens
#
async def _refresh_tokens(refresh_token: str, _client_id: str):
    try:
        async with httpx.AsyncClient(verify=SSO_CERTIFICATE) as client:
            res = await client.post(SSO_REFRESH_TOKEN_URL, json = dict(refresh_token = refresh_token))
            if res.status_code == httpx.codes.OK:
                obj = res.json()
                #
                #   Validate external access token
                #
                _new_access_token = obj['access_token']
                _new_access_token_obj = validate_external_access_token(_new_access_token, _client_id)
                if _new_access_token_obj is None:
                    raise HTTPException(status_code=401, detail='SSO gave invalid token1')
                #
                #   Validate external refresh token
                #
                _new_refresh_token = obj['refresh_token']
                _new_refresh_token_obj = validate_external_refresh_token(_new_refresh_token)
                if _new_refresh_token_obj is None:
                    raise HTTPException(status_code=401, detail='SSO gave invalid token2')
                #
                #   Validate Id token
                #
                _new_id_token = None
                if 'id_token' in obj:
                    _new_id_token = obj['id_token']
                    _new_id_token_obj = validate_id_token(_new_id_token, _client_id)
                
                return dict(expires_in = obj['expires_in'],
                            access_token = _new_access_token,
                            refresh_token = _new_refresh_token,
                            scope = obj['scope'],
                            id_token = _new_id_token,
                            issued_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            else:
                return None
    except Exception as e:
        logging.exception(str(e))
        return None

#
#   Make tokens valid
#
async def make_tokens_valid(user_id: int):
    try:
        row = await database.fetch_one(auth_user.select().where(auth_user.c.id == user_id))
        if row is None:
            return None
        if row['tokens'] is None:
            return None
        
        #
        #   Refresh all tokens of this user
        #
        dctTokens = copy.deepcopy(row['tokens'])
        for _client_id in row['tokens']:
            access_token = row['tokens'][_client_id]['access_token']
            refresh_token = row['tokens'][_client_id]['refresh_token']
            if access_token in [None, ""] or refresh_token in [None, ""]:
                return None
            
            #
            #   Try to refresh tokens
            #
            obj = await _refresh_tokens(refresh_token, _client_id)
            if obj is None:
                return None
            
            #
            #   Update the token in the dictionary
            #
            dctTokens[_client_id] = obj
        
        #
        #   Update database
        #
        await database.execute(auth_user.update().where(auth_user.c.id == user_id).values(tokens = dctTokens))
        return dctTokens
    except Exception as e:
        logging.exception(str(e))
        return None

#
#   Periodic token refresher: Runs every minute
#
async def periodic_token_refresher():
    global _lst_next_token_refresh
    while True:
        try:
            if len(_lst_next_token_refresh) == 0:
                continue

            #
            #   Refresh current working list
            #
            lst_current_token_refresh = _lst_next_token_refresh
            _lst_next_token_refresh = []

            #
            #   Refresh tokens
            #
            for _id in lst_current_token_refresh:
                await make_tokens_valid(_id)
        except Exception as e:
            print(str(e))
        finally:
            await asyncio.sleep(60)



async def take_common_action(response: Response, user_id: int):
    try:
        #
        #   Verify user
        #
        row = await database.fetch_one(auth_user.select().where(auth_user.c.id == user_id))
        if row is None:
            return { 'isError': True, 'msg': 'Access denied1' }

        if IDS_CLIENT_ID not in row['tokens']:
            return { 'isError': True, 'msg': 'Access denied2' }
        #
        #   Make tokens valid
        #
        if (await make_tokens_valid(user_id)) is None:
            force_logout_user(user_id)
            clear_login_cookies(response)
            return { 'isError': True, 'msg': 'Access denied3' }
        return None
    except Exception as e:
        print(str(e))
        return { 'isError': True, 'msg': 'An error occurred. Check server logs' }

#
#   Require either role
#
def require_either_role(lstRoles: List[str], objToken: AuthTokenOut):
    lstRoles = list(set(lstRoles))
    if len(lstRoles) == 0:
        raise HTTPException(status_code = 403, detail='Access denied')

    if set(lstRoles).isdisjoint(set(objToken.roles)):
        raise HTTPException(status_code = 403, detail='Access denied')

#
#   Convinient function to check if role has the permissions
#
async def has_permission(_roles: List[str], perm: Permissions):
    if len(_roles) == 0:
        return False
    #
    #   Find role ids
    #
    grp_rows = await database.fetch_all(auth_group.select().where(auth_group.c.role.in_(_roles)))
    arr_grp_ids = [r['id'] for r in grp_rows]
    
    #
    #   Find permissions assigned to roles
    #
    perm_rows = await database.fetch_all(auth_role_perm.select().where(auth_role_perm.c.group_id.in_(arr_grp_ids)))
    return len([1 for r in perm_rows if perm.name in r['arr_perms'] ]) > 0


# #
# #   Has only role
# #
# def has_only_role(role: str, allowed_roles: List[str], objToken: AuthTokenOut):
#     if role not in objToken.roles: return False     #   Specified role is not assigned
#     if role not in allowed_roles:
#         allowed_roles.append(role)
    
#     common_roles = set([r for r in allowed_roles]).intersection(set(objToken.roles))
#     return common_roles == set(role)

#
#   Get plants
#
async def get_plant_list(user_id, dctTokens = None):
    if dctTokens is None:
        row = await database.fetch_one(auth_user.select().where(auth_user.c.id == user_id))
        dctTokens = row['tokens']
    
    url = "{}/gui/external-plants".format(IDS_BASE_URL)
    access_token = extract_access_token(dctTokens)
    id_token = extract_id_token(dctTokens)
    r = await safe_network_call( url, 
                                'GET', 
                                { 'id_token': id_token },
                                { 'authorization': 'Bearer {}'.format(access_token) },
                                None, None, None, user_id, make_tokens_valid, True)
    if r is None:
        return None
    elif r.status_code == httpx.codes.OK:
        return r.json()
    else:
        return None

#
#   Get divisions
#
async def get_divisions_list(user_id, dctTokens = None):
    if dctTokens is None:
        row = await database.fetch_one(auth_user.select().where(auth_user.c.id == user_id))
        dctTokens = row['tokens']
    
    url = "{}/gui/external-divisions".format(IDS_BASE_URL)
    access_token = extract_access_token(dctTokens)
    id_token = extract_id_token(dctTokens)

    r = await safe_network_call( url, 
                                'GET', 
                                { 'id_token': id_token },
                                { 'authorization': 'Bearer {}'.format(access_token) },
                                None, None, None, user_id, make_tokens_valid, True)
    if r is None:
        return None
    elif r.status_code == httpx.codes.OK:
        return r.json()
    else:
        return None


#
#   Get worker details
#
async def get_single_worker_details(person_id: int, user_id: int, dctTokens = None):
    if dctTokens is None:
        row = await database.fetch_one(auth_user.select().where(auth_user.c.id == user_id))
        dctTokens = row['tokens']
    
    url = "{}/gui/external-personal-details".format(IDS_BASE_URL)
    access_token = extract_access_token(dctTokens)
    id_token = extract_id_token(dctTokens)

    r = await safe_network_call( url, 
                                'GET', 
                                { 'search_val': '', 'page_num': 0, 'person_id': person_id, 'id_token': id_token },
                                { 'authorization': 'Bearer {}'.format(access_token) },
                                None, None, None, user_id, make_tokens_valid, True)
    if r is None:
        return None
    elif r.status_code == httpx.codes.OK:
        return r.json()
    else:
        return None

#
#   Get worker counts
#
async def get_workers_count(page_num, search_val, person_id, access_token, id_token, user_id):
    url = "{}/gui/external-personal-details-count".format(IDS_BASE_URL)
    r = await safe_network_call( url, 
                                'GET', 
                                { 'search_val': search_val, 'page_num': page_num, 'person_id': person_id, 'id_token': id_token },
                                { 'authorization': 'Bearer {}'.format(access_token) },
                                None, None, None, user_id, make_tokens_valid, True)
    if r is None:
        return 0
    elif r.status_code == httpx.codes.OK:
        return r.json()['count']
    else:
        return 0

#
#   Get TLDs
#
async def get_tld_list(user_id: int, dctTokens = None):
    if dctTokens is None:
        row = await database.fetch_one(auth_user.select().where(auth_user.c.id == user_id))
        dctTokens = row['tokens']
    
    url = "{}/gui/external-tlds".format(IDS_BASE_URL)
    access_token = extract_access_token(dctTokens)
    id_token = extract_id_token(dctTokens)

    r = await safe_network_call( url, 
                                'GET', 
                                { 'id_token': id_token },
                                { 'authorization': 'Bearer {}'.format(access_token) },
                                None, None, None, user_id, make_tokens_valid, True)
    if r is None:
        return None
    elif r.status_code == httpx.codes.OK:
        return r.json()
    else:
        return None

#
#   Fetch worker photo
#
async def fetch_worker_photo(person_id: int, user_id: int):
    try:
        #
        #   Connect with IDS Portal
        #
        row = await database.fetch_one(auth_user.select().where(auth_user.c.id == user_id))
        url = "{}/gui/external-person-photo".format(IDS_BASE_URL)
        access_token = extract_access_token(row['tokens'])
        id_token = extract_id_token(row['tokens'])

        r = await safe_network_call( url, 
                                    'GET', 
                                    { 'person_id': person_id, 'id_token': id_token },
                                    { 'authorization': 'Bearer {}'.format(access_token) },
                                    None, None, None, user_id, make_tokens_valid, True)
        
        if r is None:
            return None, None
        else:
            return r.iter_bytes(), r.content

    except Exception as e:
        print(str(e))
        return None, None



#
#   =======================================================================================================================================================================
#

#
#   Generate sha256 hash of the data
#
def get_sha256_hash(data: str):
    b_data = data.encode('utf-8')
    return hashlib.sha256(b_data).hexdigest().upper()

#
#   Digitally sign report contents
#
def generated_sign_of_reports(html_data: str):
    dt = datetime.now(timezone.utc)
    future_date = dt + timedelta(minutes = 120)     #   Report contents valid for 2 hours only
    payload = dict( iat = dt, 
                    exp = future_date, 
                    iss = ISSUER, 
                    aud = ISSUER,
                    mhash = get_sha256_hash(html_data),
                    ttype = 'DATA-TOKEN')
    token = jwt.encode(payload, DATA_SECRET_KEY, algorithm = ALGORITHM)
    return token

#
#   Validate local data token and returns expected hash
#
def get_expected_hash(token: str):
    try:
        token = jwt.decode(token, DATA_SECRET_KEY, algorithms=[ALGORITHM], issuer=ISSUER, audience = ISSUER)
        #
        #   Check required fields
        #
        requiredFields = ['mhash', 'ttype', 'aud']
        for f in requiredFields:
            if f not in token:
                return None
        if token['ttype'] != 'DATA-TOKEN':
            return None
        
        return token['mhash']
    except Exception as e:
        print(str(e))
        return None

