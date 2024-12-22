from sqlalchemy import (Column, Integer, MetaData, String, Table, Text, Boolean, create_engine, ARRAY, DateTime, ForeignKey)
from databases import Database
import sys, os, json, bcrypt, string, logging
from fastapi import Body, Cookie
from os import path
from datetime import datetime, timedelta
import jwt as pyjwt
from jose import jwt
from typing import List
import httpx, math, logging
from statistics import mean

_path = path.join(path.dirname(__file__), '..', '..')
_path = os.path.abspath(_path)
_path = path.join(_path, "common")
sys.path.append(_path)

from db_common import *

VALID_WORKER_TYPES = ['Employee', 'Contract worker', 'Trainee', 'Other']


#
#   Parse scopes
#
def parse_scope_string(scope_str, default_client_id):
    arrScopes = list(set(scope_str.split(' ') if scope_str not in [None, ""] else []))
    arrScopes = [s for s in arrScopes if s not in [None, ""]]
    #
    #   Find requested scopes for each app
    #
    dctScopes = dict()
    for s in arrScopes:
        _client_id = None
        _scopes = None
        if '::' in s:
            _client_id, _scopes = s.split('::')
        else:
            _client_id, _scopes = default_client_id, s
        _scopes = [s for s in _scopes.split(':') if s not in [None, ""]]
        dctScopes[_client_id] = _scopes
    if default_client_id not in dctScopes:
        dctScopes[default_client_id] = []
    return dctScopes


# ########################################################################################################################
# ####################################      Auth code and access token     ###############################################
#
#   Generate auth code token. To avoid accessing the disk
#
@database.transaction()
async def generate_auth_code(client_db_id: int, arrScopes: List[str], logged_in_user_id: int, redirect_uri: str):
    code = generate_random_string(36)
    dt = datetime.now()
    valid_upto = dt + timedelta(minutes = AUTH_CODE_EXPIRE_MINUTES)
    _id = (await database.fetch_one(tbl_AuthCodes.insert().returning(tbl_AuthCodes.c.id).values(auth_code = code,
                                                                                                app_id = client_db_id,
                                                                                                scopes = arrScopes,
                                                                                                user_id = logged_in_user_id,
                                                                                                valid_upto = valid_upto,
                                                                                                redirect_uri = redirect_uri,
                                                                                                created_on = dt )))[0]
    auth_code = '{}:{}'.format(code, _id)
    await database.execute(tbl_AuthCodes.update().where(tbl_AuthCodes.c.id == _id).values(auth_code = auth_code))
    return auth_code


#
#   Sanitize comments
#
def safe_comments(data: str):
    ret = ""
    for ch in data:
        if (ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or ch in [' ', ':', '.', "'", ',', '!']:
            ret += ch
    return ret

#
#   Safe file name
#
def safe_filename(data: str):
    return "".join([d for d in data if d in string.digits + string.ascii_letters + '-_. '])

#
#   Safe call for external router
#
async def safe_network_call(url: str, method: str, params = None, headers = None, data = None, files = None, _json = None, user_id = None, token_func_ref = None, retry=True):
    dctArgs = dict()
    if params is not None:
        dctArgs['params'] = params
    if headers is not None:
        dctArgs['headers'] = headers
    if data is not None:
        dctArgs['data'] = data
    if files is not None:
        dctArgs['files'] = files
    if _json is not None:
        dctArgs['json'] = _json
    try:
        async with get_httpx_client() as client:
            r = None
            #
            #   GET request
            #
            if method in ['GET', 'get']:
                r = await client.get(url, **dctArgs)
            #
            #   POST request
            #
            elif method in ['POST', 'post']:
                r = await client.post(url, **dctArgs)
            #
            #   PUT request
            #
            elif method in ['PUT', 'put']:
                r = await client.put(url, **dctArgs)
            
            #
            #   DELETE request
            #
            elif method in ['DELETE', 'delete']:
                r = await client.delete(url, **dctArgs)
            else:
                return None

            #
            #   General code
            #    
            if r.status_code == httpx.codes.OK:
                return r
            elif r.status_code == 401:

                #
                #   Try to refresh code
                #
                if (retry == False) or (user_id is None) or (token_func_ref is None):
                    return r
                else:
                    dctTokens = await token_func_ref(user_id)
                    if dctTokens is None:
                        #
                        #   Refresh tokens failed
                        #
                        return r
                    else:
                        #
                        #   Refresh succeeded
                        #
                        _id_token = extract_id_token(dctTokens)
                        _access_token = extract_access_token(dctTokens)
                        if _id_token in [None, ""] or _access_token in [None, ""]:
                            return r
                        
                        #
                        #   Update params
                        #
                        if params is not None and 'id_token' in params:
                            params['id_token'] = _id_token
                        if headers is not None and 'authorization' in headers:
                            headers['authorization'] = 'Bearer {}'.format(_access_token)
                        
                        #
                        #   Make call with updated tokens
                        #
                        return await safe_network_call( url, method, params, headers, data, files, _json, user_id, token_func_ref, False)
            else:
                return r
    except Exception as e:
        print(str(e))
        if retry:
            return await safe_network_call(url, method, params, headers, data, files, _json, user_id, token_func_ref, False)
        else:
            return None