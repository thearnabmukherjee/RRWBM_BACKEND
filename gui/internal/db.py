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
from dependencies import *

