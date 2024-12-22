from typing import List
from fastapi import Header, APIRouter, Body, Depends
from fastapi import FastAPI, HTTPException, WebSocket, Depends, WebSocketDisconnect, File, UploadFile
from internal.db import *
from sqlalchemy import *
import random, uuid, base64, bcrypt
import string, json, math, logging, os
from datetime import datetime, timedelta
from jose import jwt
from starlette.requests import Request
from urllib.parse import urlencode, quote_plus
from pydantic import BaseModel, Field
from enum import Enum


class PersonalDetailsIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=512)
    empno: str = Field(..., max_length=512)
    dob: str = Field(..., max_length=10, min_length=10)
    doj: str = Field(..., max_length=10, min_length=10)
    firm_name: str = Field(..., min_length=1, max_length=512)
    gender: str = Field(..., max_length=512)
    fingerprints: str = Field(None)
    is_worker: str = Field(..., min_length=1, max_length=1)
    photo: str = Field(..., min_length=100)
    remarks: str = Field(None, max_length=512)
    