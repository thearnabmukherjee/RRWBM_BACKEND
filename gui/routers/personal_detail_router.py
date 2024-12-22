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
from models.PersonalDetailsIn import *

app = APIRouter()
WORKER_PHOTO_URL = ''

#
#   Get list of personal details
#
@app.get("/")
async def get_personal_details( response: Response,
                                search_val: str = Query(None),
                                page_num: int = Query(..., ge=0), 
                                objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.LIST_REGISTERED_WORKERS):
        raise HTTPException(status_code = 403, detail = "Access denied")

    try:
        obj = await take_common_action(response, objToken.id)
        if obj is not None:
            return obj
        
        if search_val not in [None, ""]:
            search_val = "".join([c for c in search_val if c in string.ascii_letters + string.digits + ' -_'])

        if search_val in [None, ""]:
            search_val = "%"
        else:
            #
            #   See if it is a date
            #
            try:
                dt = datetime.strptime(search_val, '%d-%m-%Y')
                search_val = dt.strftime('%Y-%m-%d')
            except:
                pass

            search_val = "%{}%".format(search_val)
        #
        #   Connect with IDS portal
        #
        row = await database.fetch_one(auth_user.select().where(auth_user.c.id == objToken.id))

        #
        #   Make network call
        #
        url = "{}/gui/external-personal-details".format(IDS_BASE_URL)
        access_token = extract_access_token(row['tokens'])
        id_token = extract_id_token(row['tokens'])
        r = await safe_network_call( url, 
                                'GET', 
                                dict(page_num = page_num, search_val = search_val, person_id = 0, id_token = id_token),
                                { 'authorization': 'Bearer {}'.format(access_token) },
                                None, None, None, objToken.id, make_tokens_valid, True)
        
        if r is not None:
            if r.status_code == httpx.codes.OK:
                #
                #   Extract worker records
                #
                obj = r.json()
                if len(obj) > 0:
                    for dct in obj:
                        dct['photo_url'] = WORKER_PHOTO_URL + "?worker_id=" + str(dct['id'])
                    
                    #
                    #   Add registered by name also
                    #
                    rows = await database.fetch_all(auth_user.select())
                    dctUsers = { x['sso_id']: x['username'] for x in rows }
                    _lst = []
                    for dct in obj:
                        dct = copy.deepcopy(dct)
                        if 'created_by' in dct:
                            dct['created_by_name'] = dctUsers[dct['created_by']] if dct['created_by'] in dctUsers else '-NA-'
                        else:
                            dct['created_by_name'] = '-NA-'
                        _lst.append(dct)
                    obj = _lst
                #
                #   Extract worker counts
                #
                _count = await get_workers_count(page_num, search_val, 0, access_token, id_token, objToken.id)
                return { 'isError': False, 'msg': obj, 'count': _count }

        return { 'isError': True, 'msg': 'An error occurred' }
    except Exception as e:
        print(str(e))
        return { 'isError': True, 'msg': 'An error occurred. Check server logs' }

#
#   Create new personal details
#
@app.post("/")
async def create_personal_detail(response: Response,
                                 data: PersonalDetailsIn,
                                 objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.REGISTER_WORKER):
        raise HTTPException(status_code = 403, detail = "Access denied")
    try:
        obj = await take_common_action(response, objToken.id)
        if obj is not None:
            return obj
        #
        #   Connect with IDS portal
        #
        row = await database.fetch_one(auth_user.select().where(auth_user.c.id == objToken.id))
        
        #
        #   Prepare network arguments
        #
        url = "{}/gui/external-personal-details".format(IDS_BASE_URL)
        access_token = extract_access_token(row['tokens'])
        id_token = extract_id_token(row['tokens'])

        #
        #   Prepare photo file
        #
        _photo = base64.b64decode(data.photo)
        _photo = io.BytesIO(_photo)

        #
        #   Prepare fingerprints file
        #
        _fp = None
        if data.fingerprints not in [None, ""]:
            _fp = base64.b64decode(data.fingerprints)
            _fp = io.BytesIO(_fp)
        
        #
        #   Prepare files to be uploaded
        #
        dctFiles = { 'photo': _photo }
        if _fp is not None:
            dctFiles['fp'] = _fp
        
        #
        #   Submit data
        #
        _data = data.dict()
        del _data['fingerprints']
        del _data['photo']
        _data['is_worker'] = _data['is_worker'] in ['t', 'T']

        r = await safe_network_call( url, 
                                    'POST', 
                                    { 'id_token': id_token },
                                    { 'authorization': 'Bearer {}'.format(access_token) },
                                    _data, dctFiles, None, objToken.id, make_tokens_valid, True)
        if r is None:
            return { 'isError': True, 'msg': 'An error occurred' }
        elif r.status_code == httpx.codes.OK:
            obj = r.json()
            return obj
        elif r.status_code == 403:
            return { 'isError': True, 'msg': 'You do not have enough permissions for new registration' } 
         
        return { 'isError': True, 'msg': 'An error occurred' }
    except Exception as e:
        print(str(e))
        return { 'isError': True, 'msg': 'An error occurred. Check server logs' }


#
#   Get personal details of a person
#
@app.get("/specific")
async def get_personal_detail(  response: Response,
                                person_id: int = Query(..., ge=1),
                                objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.SEE_WORKER_DETAILS):
        raise HTTPException(status_code = 403, detail = "Access denied")
    try:
        obj = await take_common_action(response, objToken.id)
        if obj is not None:
            return obj
        
        res = await get_single_worker_details(person_id, objToken.id, None)
        if res is None or len(res) == 0:
            return { 'isError': True, 'msg': 'Could not find the registered person in IDS Portal' }
        else:
            res = res[0]
            res['photo_url'] = WORKER_PHOTO_URL + "?worker_id=" + str(res['id'])
            
            #
            #   Add registered by info if available
            #
            if 'created_by' in res:
                _auth_row = await database.fetch_one(auth_user.select().where(auth_user.c.sso_id == res['created_by']))
                res['created_by_name'] = '-NA-' if _auth_row is None else _auth_row['username']
            else:
                res['created_by_name'] = '-NA-'
            return { 'isError': False, 'msg': res }
    except Exception as e:
        logging.exception(str(e))
        return { 'isError': True, 'msg': 'An error occurred. Check server logs' }

#
#   Download worker photo
#
@app.get("/worker-photo")
async def get_worker_photo( response: Response,
                            worker_id: int = Query(..., ge=1),
                            objToken: AuthTokenOut = Depends(dp_get_current_user_from_cookie)):
    if not await has_permission(objToken.roles, Permissions.DOWNLOAD_WORKER_PHOTO):
        raise HTTPException(status_code = 403, detail = "Access denied")

    try:
        obj = await take_common_action(response, objToken.id)
        if obj is not None:
            return None
        
        res, _ = await fetch_worker_photo(worker_id, objToken.id)
        if res is None:
            return None

        return StreamingResponse(res, media_type="image/png")
    except Exception as e:
        print(str(e))
        return None


