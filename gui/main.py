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
import routers.division_router
import routers.personal_detail_router
import routers.plants_router
import routers.tld_router
import routers.intake_router
import routers.nuclide_router
import routers.geometry_router
import routers.class_router
import routers.dataset_router


app = FastAPI()

app.include_router(routers.division_router.app, prefix='/division', tags=['Division management'])
app.include_router(routers.personal_detail_router.app, prefix='/pd', tags=['Worker registration management'])
app.include_router(routers.plants_router.app, prefix='/plant', tags=['Plants management'])
app.include_router(routers.tld_router.app, prefix='/tld', tags=['TLD management'])
app.include_router(routers.intake_router.app, prefix='/intake-route', tags=['Intake route management'])
app.include_router(routers.nuclide_router.app, prefix='/nuclide', tags=['Radionuclide management'])
app.include_router(routers.geometry_router.app, prefix='/geometry', tags=['Geometry management'])
app.include_router(routers.class_router.app, prefix='/class', tags=['Solubility class management'])
app.include_router(routers.dataset_router.app, prefix='/dataset', tags=['Dataset management'])


@app.on_event("startup")
async def startup():
    await database.connect()

    #
    #   Find all permissions role
    #
    if await database.execute(auth_group.count()) == 0:
        await database.execute(auth_group.insert().returning(auth_group.c.id).values(role = 'All perm'))
    group_id = (await database.fetch_one(auth_group.select().where(auth_group.c.role == "All perm")))['id']

    #
    #   Assign all permissions to the default role
    #
    if (await database.execute(auth_role_perm.count())) == 0:
        _arr_perm = [(e.name, e.value) for e in Permissions]
        await database.execute(auth_role_perm.insert().values(group_id = group_id, arr_perms = [p[0] for p in _arr_perm]))
        
        #
        #   Assign role the default user
        #
        if (await database.execute(auth_membership.count())) == 0:
            user_row = await database.fetch_one(auth_user.select())
            if user_row is not None:
                await database.execute(auth_membership.insert().values(group_id = group_id, user_id = user_row['id']))



@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()