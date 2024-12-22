from sqlalchemy import (Column, Integer, MetaData, String, Table, Text, Boolean, create_engine, ARRAY, DateTime, ForeignKey, JSON, desc, BigInteger, Float, asc, Date)
from databases import Database
from pydantic import BaseModel
from typing import List, Dict, Optional
from fastapi import HTTPException, Header, Depends, Query, Response
import sys, os, json, socket, bcrypt, base64, secrets
from os import path
from jose import jwt
from enum import Enum
from datetime import datetime, timedelta, date, timezone
import httpx, logging
from mako.template import Template
from mako.lookup import TemplateLookup
import pdfkit, ssl, redis
import aiosmtplib, string
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

#
# ==========================================    Load configuration info ======================================================
#
_cf = path.join(path.dirname(__file__), '..')
_cf = os.path.abspath(_cf)
_cf = path.join(_cf, "common")
_arr_dir = [
    path.join(_cf, "templates"), 
    path.join(_cf, "templates", "email"), 
    path.join(_cf, "templates", "reports"),
    path.join(_cf, "templates", "10H")
]
my_lookup = TemplateLookup(directories = _arr_dir)
_cf = path.join(_cf, "config.json")

objConfig = None
with open(_cf, "r", encoding='utf-8') as f:
    objConfig = json.loads(f.read())

EXTERNAL_PUBLIC_KEY = objConfig['public-key-path']
EXTERNAL_ALGORITHM = objConfig['external-algorithm']
SSO_TOKEN_URL = objConfig['sso-token-url']
SSO_REFRESH_TOKEN_URL = objConfig['sso_refresh_token_url']
SSO_ISSUER = objConfig['sso_issuer']
SSO_REDIRECT_URI = objConfig['sso-gives-auth-code-on-page']
SSO_CERTIFICATE = objConfig['sso-certificate']
SSO_SIGN_URL = objConfig['sso_sign_url']
MY_CLIENT_ID = objConfig['my_client_id']
MY_CLIENT_SECRET = objConfig['my_client_secret']
WKHTML_TO_PDF_PATH = objConfig['path-wkthmltopdf-executable']
EXTERNAL_ACCESS_TOKEN_EXPIRE_MINUTES = objConfig['external-access-token-expiration-minutes']          #   For external token
EXTERNAL_REFRESH_TOKEN_EXPIRE_MINUTES = objConfig['external_refresh_token_expiration_minutes']        #   For external token


EMAIL_HOST_NAME = objConfig['email-server-ip']
EMAIL_PORT = objConfig['email-server-port']
EMAIL_SENDER = objConfig['email-from']

LOCAL_TOKEN_SECRET = objConfig['local_token_secret_key']
LOCAL_TOKEN_EXPIRE_MINUTES = objConfig['local_token_expire_minutes']
LOCAL_REFRESH_TOKEN_EXPIRE_MINUTES = objConfig['local_refresh_token_expire_minutes']
ALGORITHM = objConfig['token_algorithm']
ISSUER = objConfig['token_issuer']
KNOWN_CLIENT_IDS = objConfig['known_client_ids']

BCRYPT_ROUNDS = objConfig['bcrypt_rounds']

IDS_BASE_URL = objConfig["ids-base-url"]
IDS_CLIENT_ID = objConfig['ids-client-id']
IDS_CERTIFICATE = objConfig['ids-certificate']

REDIS_IP = objConfig['redis_ip']
REDIS_PORT = objConfig['redis_port']
REDIS_DB_NUMBER = objConfig['redis_db_number']

MY_DIVISION = objConfig['my_division']
MY_SECTION = objConfig['my_section']
DATA_SECRET_KEY = objConfig['data-secret-token']
COOKIE_PATH_PREFIX = objConfig['cookie-path']


VALID_WORKER_TYPES = ['Employee', 'Contract worker', 'Trainee', 'Other']

with open(EXTERNAL_PUBLIC_KEY, 'rb') as f:
    EXTERNAL_PUBLIC_KEY = f.read()
    f.close()

#
# ===============================================   Email =============================================================
#
async def send_email(to: str, lstCC : List[str], subject: str, msg: str):
    #
    #   Prepare message
    #
    message = MIMEMultipart("alternative")
    message["From"] = EMAIL_SENDER
    message["To"] = to
    if lstCC is not None and len(lstCC) > 0:
        message['Cc'] = lstCC
    message["Subject"] = subject
    final_message = MIMEText(msg, "html", "utf-8") if msg.startswith("<html>") else MIMEText(msg, "plain", "utf-8")
    message.attach(final_message)

    #
    #   Pepare SSL disabled context
    #
    _is_disable_ssl = os.environ['email-disable-ssl'] in [True, 't', 'T', 'True', 'true']
    ssl_context = ssl.create_default_context()
    if _is_disable_ssl:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    #
    #   Send the email message
    #
    _username = os.environ['email-username']
    _password = os.environ['email-password']
    async with aiosmtplib.SMTP(hostname = EMAIL_HOST_NAME, port = EMAIL_PORT, tls_context = ssl_context, start_tls = not _is_disable_ssl) as smtp:
        await smtp.login(_username, _password)
        await smtp.send_message(message)


#
# ===============================================   Database related tasks  ============================================
#

DATABASE_URL = 'postgresql://{}:{}@{}/{}'.format(objConfig['db_username'], 
                                                objConfig['db_password'], 
                                                objConfig['db_server_ip'], 
                                                objConfig['db_name'])

engine = create_engine(DATABASE_URL)
metadata = MetaData()

auth_user = Table('auth_user', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('sso_id', Integer, unique=True, nullable=False),
                Column('username', String(50)),
                Column('first_name', String(50)),
                Column('last_name', String(50)),
                Column('email', String(100)),
                Column('status', String(512), nullable=True),
                Column('tokens', JSON))


auth_group = Table('auth_group', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('role', String(300)))


auth_membership = Table('auth_membership', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('group_id', Integer, ForeignKey('auth_group.id')),
                Column('user_id', Integer, ForeignKey('auth_user.id')))


auth_role_perm = Table('auth_role_perm', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('group_id', Integer, ForeignKey('auth_group.id')),
                Column('arr_perms', ARRAY(String(100)), nullable=False))


tbl_ValidAuthState = Table('tbl_ValidAuthState', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('state', String(36), nullable=False, unique=True),
                Column('valid_till', DateTime, nullable=False))


tbl_HP_Plant_Binding = Table('tbl_HP_Plant_Binding', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('hp_id', Integer, ForeignKey('auth_user.id'), nullable=False),
                Column('plant_id', Integer, nullable=False),
                Column('plant_name', String(512), nullable=False))


#
#   Divisions
#
tbl_Divisions = Table('tbl_Divisions', metadata,
                Column('id', Integer, primary_key=True),
                Column('abbr', String(512), nullable=False),
                Column('description', String(512), nullable=False),
                Column('is_active', Boolean, nullable=False),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer))

#
#   Plants
#
tbl_Plants = Table('tbl_Plants', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(512)),
                Column('plocation', String(512)),
                Column('is_strategic', Boolean, nullable=False, default=False),
                Column('is_active', Boolean, nullable=False, default=False),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer))

#
#   Intake routes
#
tbl_IntakeRoutes = Table('tbl_IntakeRoutes', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(512), nullable=False),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer))

#
#   Radionuclides
#
tbl_Radionuclides =   Table('tbl_Radionuclides', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(100), nullable=False),
                Column('mda', Float, nullable=True),
                Column('arr_energy', ARRAY(Float), nullable=True),
                Column('arr_yield', ARRAY(Float), nullable=True),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))

#
#   Personal details
#
tbl_PersonalDetails =   Table('tbl_PersonalDetails', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(100), nullable=False),
                Column('empno', String(100), nullable=False),
                Column('dob', Date, nullable=False),
                Column('doj', Date, nullable=False),
                Column('firm_name', String(100), nullable=False),
                Column('gender', String(20), nullable=False),
                Column('fingerprints', Text),
                Column('is_worker', Boolean, nullable=False, default=False),
                Column('photo', String(512)),
                Column('remarks', Text),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))


#
#   Geometry
#
tbl_Geometry =  Table('tbl_Geometry', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(100), nullable=False),
                Column('is_active', Boolean, nullable=False, default=False),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))


#
#   Capability
#
tbl_Capability = Table('tbl_Capability', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('mtype', String(100), nullable=False),           #   MCA type
                Column('status', String(100), nullable=False, default='OFFLINE'),                   #   OFFLINE, BUSY, IDLE
                Column('geometry_id', Integer, ForeignKey('tbl_Geometry.id'), nullable=False),
                Column('operating_mode', String(15), nullable=False),
                Column('last_ping_on', DateTime, nullable=True),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))


#
#   Classes
#
tbl_Classes =   Table('tbl_Classes', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(100), nullable=False),
                Column('is_active', Boolean, nullable=False, default=False),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))

#
#   Dataset
#
tbl_DataSet =   Table('tbl_DataSet', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(100), nullable=False),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))

#
#   MCA config
#
tbl_MCAConfig = Table('tbl_MCAConfig', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(100), nullable=False, unique=True),
                Column('capability', String(50), nullable=False),
                Column('mca_config', JSON, nullable=False),
                Column('geometry_id', Integer, ForeignKey('tbl_Geometry.id'), nullable=False),
                Column('is_active', Boolean, nullable=False, default=False),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))

#
#   Energy calibration
#
tbl_EnergyCalibrations = Table('tbl_EnergyCalibrations', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(100), nullable=False),
                Column('axx', Float, nullable=False),
                Column('bx', Float, nullable=False),
                Column('constant', Float, nullable=False),
                Column('duration', Integer, nullable=False),
                Column('mca_config_id', Integer, ForeignKey('tbl_MCAConfig.id'), nullable=False),
                Column('geometry_id', Integer, ForeignKey('tbl_Geometry.id'), nullable=False),
                Column('spec_data', ARRAY(Integer), nullable=False),
                Column('is_active', Boolean, nullable=False, default=False),
                Column('operating_mode', String(15), nullable=False),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))

#
#   Other spectrum files
#
tbl_OtherSpectrumFiles = Table('tbl_OtherSpectrumFiles', metadata,              #   Background, Efficiency
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(100), nullable=False),
                Column('spec_data', JSON, nullable=False),
                Column('fileType', String(50), nullable=False),
                Column('duration', Integer, nullable=False),
                Column('geometry_id', Integer, ForeignKey('tbl_Geometry.id'), nullable=True),
                Column('capability', String(50), nullable=False),
                Column('mca_config_id', Integer, ForeignKey('tbl_MCAConfig.id'), nullable=False),
                Column('energy_cal_id', Integer, ForeignKey('tbl_EnergyCalibrations.id'), nullable=False),
                Column('is_active', Boolean, nullable=False, default=False),
                Column('operating_mode', String(15), nullable=False),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))

#
#   Monitoring details
#
tbl_MonitoringDetails =   Table('tbl_MonitoringDetails', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('umi', String(50), nullable=False),
                Column('is_dae', Boolean, nullable=False, default=False),
                Column('division', Integer, nullable=False),
                Column('plant', Integer, nullable=False),
                Column('weight', Float, nullable=True),
                Column('height', Float, nullable=True),
                Column('work_type', String(100), nullable=False),
                Column('monitoring_type', String(50), nullable=False),
                Column('intake_routes', ARRAY(String(100)), nullable=False),
                Column('nuclides_handled', ARRAY(Integer), nullable=False),
                Column('lstROI', JSON, nullable=False),
                Column('lstWatches', JSON, nullable=False),
                Column('accident_history', Text),
                Column('comments', Text),
                Column('is_analysis_done', Boolean, nullable=False, default=False),
                Column('bg_spectrum', Integer, ForeignKey('tbl_OtherSpectrumFiles.id'), nullable=False),
                Column('spectrum', JSON),
                Column('contribution_method', String(50), nullable=False, default="STRIPPING"),
                Column('contribution_id', Integer, nullable=False),
                Column('dataset_id', Integer, ForeignKey('tbl_DataSet.id'), nullable=False),
                Column('geometry_id', Integer, ForeignKey('tbl_Geometry.id'), nullable=False),
                Column('cal_id', Integer, ForeignKey('tbl_EnergyCalibrations.id'), nullable=False),
                Column('person_id', Integer, nullable=False),       #   Could be negative if orphan
                Column('h10_id', Integer, nullable=False),          #   Could be negative if orphan
                Column('mon_status', String(50), nullable=False),
                Column('mon_status_comments', Text, nullable=True),
                Column('monitored_on', Date, nullable=False),
                Column('intake_date', Date, nullable=False),
                Column('system_comments', Text, nullable=True),
                Column('is_recalled', Boolean, nullable=False, default=False),
                Column('last_recall_date', DateTime, nullable=True),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False),
                Column('modified_on', DateTime, nullable=True),
                Column('modified_by', Integer, ForeignKey('auth_user.id'), nullable=True))

#
#   10H form
#
tbl_10H = Table('tbl_10H', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(100), nullable=False),
                Column('tld', String(100)),
                Column('comp_code', String(100)),
                Column('empno', String(100)),
                Column('gender', String(20), nullable=False),
                Column('weight', Float, nullable=False),
                Column('height', Float, nullable=False),
                Column('chest', Float, nullable=False),
                Column('doj', DateTime, nullable=False),
                Column('age', Integer),
                Column('dob', DateTime),
                Column('division_id', Integer, ForeignKey('tbl_Divisions.id'), nullable=False),
                Column('plant_id', Integer, ForeignKey('tbl_Plants.id'), nullable=False),
                Column('person_id', Integer, ForeignKey('tbl_PersonalDetails.id'), nullable=True),
                Column('duration', Date),
                Column('duration_comments', String(200)),
                Column('type_of_process', String(200)),
                Column('type_of_process_comments', String(200)),
                Column('monitoring_type', String(20), nullable=False),
                Column('exposure_time', Date),
                Column('exposure_time_comments', String(200)),
                Column('intake_route_ids', ARRAY(Integer), nullable=False),
                Column('nuclide_ids', ARRAY(Integer), nullable=False),
                Column('isotopic_comp', String(200)),
                Column('pu_am_ratio', String(200)),
                Column('particle_size', String(200)),
                Column('particle_size_comments', String(200)),
                Column('therapeutic_treatment', String(200)),
                Column('collection_duration', String(200)),
                Column('collection_duration_comments', String(200)),
                Column('previous_monitoring', DateTime),
                Column('last_iodination_day', Date),
                Column('last_iodination_day_comments', String(400)),
                Column('sender_id', Integer, ForeignKey('auth_user.id'), nullable=False),
                Column('sent_on', DateTime, nullable=False),
                Column('mon_id', Integer, ForeignKey('tbl_MonitoringDetails.id'), nullable=True),
                Column('worker_type', String(20), nullable=False),
                Column('status', String(30), nullable=False),
                Column('comments', String(800)),
                Column('incidence_description', String(800)),
                Column('requested_schedule_date', DateTime),
                Column('scheduled_date', DateTime),
                Column('completion_date', DateTime),
                Column('hp_id', Integer, ForeignKey('auth_user.id'), nullable=False),
                Column('follow_up_of', Integer, ForeignKey('tbl_10H.id'), nullable=True),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))


#
#   Contribution factors
#
tbl_ContributionFactors = Table('tbl_ContributionFactors', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(100), nullable=False, unique=True),
                Column('capability', String(50), nullable=False),
                Column('geometry_id', Integer, ForeignKey('tbl_Geometry.id'), nullable=False),
                Column('data', JSON, nullable=False),
                Column('is_active', Boolean, nullable=False, default=False),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))

#
#   Retained fractions
#
tbl_RetainedFractions = Table('tbl_RetainedFractions', metadata,
                        Column('id', Integer, primary_key=True, autoincrement=True),
                        Column('nuclide_id', Integer, ForeignKey('tbl_Radionuclides.id'), nullable=False),
                        Column('class_id', Integer, ForeignKey('tbl_Classes.id'), nullable=False),
                        Column('route_id', Integer, ForeignKey('tbl_IntakeRoutes.id'), nullable=False),
                        Column('dataset_id', Integer, ForeignKey('tbl_DataSet.id'), nullable=False),
                        Column('days', Integer, nullable=False),
                        Column('retained_fraction', Float, nullable=False),
                        Column('created_on', DateTime, nullable=False),
                        Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))


#
#   Dose coefficients
#
tbl_DoseCoeff = Table('tbl_DoseCoeff', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('nuclide_id', Integer, ForeignKey('tbl_Radionuclides.id'), nullable=False),
                Column('class_id', Integer, ForeignKey('tbl_Classes.id'), nullable=False),
                Column('route_id', Integer, ForeignKey('tbl_IntakeRoutes.id'), nullable=False),
                Column('dataset_id', Integer, ForeignKey('tbl_DataSet.id'), nullable=False),
                Column('dose_coeff', Float, nullable=False),
                Column('created_on', DateTime, nullable=False),
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))

#
#   Efficiency calibration factors
#
tbl_EffFactors = Table('tbl_EffFactors', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('nuclide_id', Integer, ForeignKey('tbl_Radionuclides.id'), nullable=False),
                Column('geometry_id', Integer, ForeignKey('tbl_Geometry.id'), nullable=False),
                Column('capability', String(50), nullable=False),
                Column('dataset_id', Integer, ForeignKey('tbl_DataSet.id'), nullable=False),
                Column('effFactor', Float, nullable=False),
                Column('created_on', DateTime),
                Column('created_by', Integer, ForeignKey('auth_user.id')))


#
#   Region of interest
#
tbl_ROI = Table('tbl_ROI', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('startChannel', Integer, nullable=False),
                Column('endChannel', Integer, nullable=False),
                Column('capability', String(50), nullable=False),
                Column('nuclide_id', Integer, ForeignKey('tbl_Radionuclides.id'), nullable=False),
                Column('geometry_id', Integer, ForeignKey('tbl_Geometry.id'), nullable=False),
                Column('class_id', Integer, ForeignKey('tbl_Classes.id'), nullable=False),
                Column('is_active', Boolean, nullable=False, default=False),
                Column('created_on', DateTime),  
                Column('created_by', Integer, ForeignKey('auth_user.id')))

#
#   Unique Monitroing Ids
#
tbl_UMI = Table('tbl_UMI', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('currYear', Integer, nullable=False),
                Column('nextNum', Integer, nullable=False))


#
#   Phantoms
#
tbl_Phantom = Table('tbl_Phantom', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(100), nullable=False),
                Column('is_active', Boolean, nullable=False),
                Column('created_on', DateTime, nullable=False),  
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))

#
#   Distribution
#
tbl_Distrbution = Table('tbl_Distrbution', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(100), nullable=False),
                Column('is_active', Boolean, nullable=False),
                Column('created_on', DateTime, nullable=False),  
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))

#
#   Calibration sources
#
tbl_CalibSources = Table('tbl_CalibSources', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(100), nullable=False),
                Column('energy', Float, nullable=False),
                Column('activity', Float, nullable=False),
                Column('half_life', Float, nullable=False),
                Column('nuclide_id', Integer, ForeignKey('tbl_Radionuclides.id'), nullable=False),
                Column('is_active', Boolean, nullable=False),
                Column('created_on', DateTime, nullable=False),  
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))

#
#   Efficiency calibration records
#
tbl_EffCalRecords = Table('tbl_EffCalRecords', metadata,
                Column('id', Integer, primary_key=True, autoincrement=True),
                Column('name', String(100), nullable=False),
                Column('data', JSON, nullable=False),
                Column('exported_factor_id', Integer, ForeignKey('tbl_ContributionFactors.id'), nullable=True),
                Column('geometry_id', Integer, ForeignKey('tbl_Geometry.id'), nullable=False),
                Column('mca_config_id', Integer, ForeignKey('tbl_MCAConfig.id'), nullable=False),
                Column('energy_cal_id', Integer, ForeignKey('tbl_EnergyCalibrations.id'), nullable=False),
                Column('background_id', Integer, ForeignKey('tbl_OtherSpectrumFiles.id'), nullable=False),
                Column('capability', String(50), nullable=False),
                Column('is_active', Boolean, nullable=False),
                Column('created_on', DateTime, nullable=False),  
                Column('created_by', Integer, ForeignKey('auth_user.id'), nullable=False))





database = Database(DATABASE_URL)
metadata.create_all(engine)

redis_db = redis.Redis(host=REDIS_IP, port=REDIS_PORT, db=REDIS_DB_NUMBER)


class AuthTokenOut(BaseModel):
    id: int
    username: str
    first_name: str
    last_name: str
    roles: List[str]

    class Config:
        json_encoders = {
            datetime: lambda v: v.strftime("%Y-%m-%d %H:%M:%S")
        }

def hash_password(plain_text: str):
    salt = bcrypt.gensalt(rounds = BCRYPT_ROUNDS)
    hashed_password = bcrypt.hashpw(plain_text.encode('utf-8'), salt)
    hashed_password = hashed_password.decode('utf8')
    return hashed_password


def is_password_matched(password: str, stored_hashed_password):
    return bcrypt.checkpw(bytes(password, 'utf-8'), bytes(stored_hashed_password, 'utf-8'))


def get_httpx_client():
    return httpx.AsyncClient(verify = IDS_CERTIFICATE)


def extract_access_token(dctTokens):
    return dctTokens[IDS_CLIENT_ID]['access_token']


def extract_id_token(dctTokens):
    return dctTokens[IDS_CLIENT_ID]['id_token']


#
#   Generate PDF
#
def generate_PDF(html_contents: str, footer_line: str):
        config = pdfkit.configuration(wkhtmltopdf = WKHTML_TO_PDF_PATH)
        pdf_contents_bytes = pdfkit.from_string(html_contents, 
                                                False, configuration=config, 
                                                options = {
                                                            'page-size': 'A4',
                                                            'margin-top': '10',
                                                            'margin-right': '5',
                                                            'margin-left': '15',
                                                            'margin-bottom': '20',
                                                            'zoom': '1.1',
                                                            'encoding': "UTF-8",
                                                            'dpi': '600',
                                                            'orientation': 'portrait',
                                                            'footer-left' : footer_line,
                                                            'footer-font-size' : '8',
                                                            'footer-right' : 'Page [page] of [toPage]',
                                                            'header-center': 'FORM 10H',
                                                            'quiet' : None
        })
        encoded_pdf_contents = base64.b64encode(pdf_contents_bytes)
        return encoded_pdf_contents


#
#   Blacklist local access token
#
def blacklist_local_access_token(user_id: int):
    key = 'LAT_valid_after_{}'.format(user_id)
    key_expire_seconds = LOCAL_TOKEN_EXPIRE_MINUTES * 60
    redis_db.set(key, datetime.now().timestamp(), ex = key_expire_seconds)

#
#   Blacklist local refresh token
#
def blacklist_local_refresh_token(user_id: int):
    key = 'LRT_valid_after_{}'.format(user_id)
    key_expire_seconds = LOCAL_REFRESH_TOKEN_EXPIRE_MINUTES * 60
    redis_db.set(key, datetime.now().timestamp(), ex = key_expire_seconds)

#
#   Blacklist external access token
#
def blacklist_external_access_token(user_id: int):
    key = 'EAT_valid_after_{}'.format(user_id)
    key_expire_seconds = EXTERNAL_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    redis_db.set(key, datetime.now().timestamp(), ex = key_expire_seconds)

#
#   Blacklist external refresh token
#
def blacklist_external_refresh_token(user_id: int):
    key = 'ERT_valid_after_{}'.format(user_id)
    key_expire_seconds = LOCAL_REFRESH_TOKEN_EXPIRE_MINUTES * 60
    redis_db.set(key, datetime.now().timestamp(), ex = key_expire_seconds)


#
#   Set cookies during login
#
def set_login_cookies(response: Response, access_token: str, refresh_token: str):
    response.set_cookie(key = "access_token", value = access_token, httponly = True, secure=True, path = COOKIE_PATH_PREFIX)
    response.set_cookie(key = "refresh_token", value = refresh_token, httponly = True, secure=True, path = COOKIE_PATH_PREFIX)

#
#   Clear cookies during logout
#
def clear_login_cookies(response: Response):
    try:
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
    except:
        pass

#
#   Force logout user
#
def force_logout_user(user_id: int):
    blacklist_local_access_token(user_id)
    blacklist_local_refresh_token(user_id)
    blacklist_external_access_token(user_id)
    blacklist_external_refresh_token(user_id)
    
#
#   Generate random string of specified length
#
def generate_random_string(length: int = 36):
    SPACE = string.ascii_letters + string.digits
    return "".join(secrets.choice(SPACE) for _ in range(length))


#
#   Define permissions
#
class Permissions(str, Enum):
    LIST_ALL_10H_FORMS = "List of all the 10H forms"
    LIST_ASSOCIATED_PLANT_10H_FORMS = "List of 10H forms associated with assigned plant only"
    CREATE_NEW_10H = "Create new 10H form"
    CREATE_NEW_10H_ON_BEHALF = "Create new 10H form behalf of other HPs"

    MODIFY_ANY_10H = "Modify 10H form filled by anyone"
    MODIFY_OWN_FILLED_10H = "Modify only self filled 10H forms"
    MODIFY_OWN_PLANT_10H = "Modify only those 10H forms which belong to assigned plants"
    
    PRINT_ANY_10H = "Download any 10H form as PDF"
    PRINT_OWN_FILLED_10H = "Download only self filled 10H forms as PDF"
    PRINT_OWN_PLANT_10H = "Download only those 10H forms which belong to assigned plants"

    ACCEPT_10H_FORM = "Accept 10H forms"
    REJECT_10H_FORM = "Reject 10H forms"
    CLONE_10H_FORM = "Clone 10H forms"

    LIST_DIVISIONS = "View list of divisions"
    CREATE_DIVISION = "Create new division"

    LIST_ALL_PLANTS = "View list of all the plants"
    LIST_ASSIGNED_PLANTS = "View list of only assigned plants"
    CREATE_PLANT = "Create new plant"
    
    LIST_REGISTERED_WORKERS = "View list of registered workers"
    SEE_WORKER_DETAILS = "Can see a specific registered worker details"
    REGISTER_WORKER = "Can register a new worker"
    DOWNLOAD_WORKER_PHOTO = "Can download worker photo"

    LIST_ALL_TLDS = "View list of all the TLDs"
    LIST_ASSIGNED_TLDS = "View list of only assigned TLDs"
    CREATE_TLD = "Create new TLD record"
    CHANGE_TLD_PLANT_BINDING = "Change TLD and plant assignment"

    LIST_ROLES = "Can view list of roles existing in the portal"
    CREATE_NEW_ROLE = "Can create new role"
    ASSIGN_ROLES = "Can change roles assigned to various users"
    DELETE_EXISTING_ROLE = "Can delete existing role in the system"

    LIST_PERMISSIONS = "Can see list of permissions"
    ASSIGN_PERMISSIONS = "Can change permissions assigned to a role"
    VIEW_PERMISSION_ROLE_ASSIGNMENT = "Can see permissions assigned to each existing role"

    LIST_USERS = "Can see list of users"
    LIST_USERS_WITH_ROLES = "Can see roles assigned to each user"
    BLOCK_UNBLOCK_USER_ACCOUNT = "Can block/un-block user account"

    LIST_INTAKE_ROUTES = "Can see list of intake routes"
    CREATE_INTAKE_ROUTE = "Create new intake route"

    LIST_NUCLIDES = "Can see list of nuclides"
    CREATE_NEW_NUCLIDE = "Create a new nuclide record"
    MODIFY_EXISTING_NUCLIDE = "Can modify existing nuclide record"

    LIST_GEOMETRY = "Can see list of geometries"
    CREATE_NEW_GEOMETRY = "Create new geometry"
    ENABLE_DISABLE_GEOMETRY = "Enable-disable existing geometries"

    LIST_CLASS = "Can see list of solubility classes"
    CREATE_NEW_CLASS = "Create new solubility class"
    ENABLE_DISABLE_CLASS = "Enable-disable existing solubility classes"

    LIST_DATASETS = "Can see list of datasets"
    CREATE_NEW_DATASET = "Create new dataset"


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