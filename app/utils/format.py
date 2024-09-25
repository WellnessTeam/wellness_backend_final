from datetime import datetime
from decimal import Decimal
import pytz

# KST 타임존 설정
KST = pytz.timezone('Asia/Seoul')

# 날짜 및 시간 형식을 'YYYY-MM-DD HH:MM:SS'로 포맷
def format_datetime(dt: datetime):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# datetime 객체를 ISO 8601 문자열로 변환하는 헬퍼 함수
def datetime_to_string(dt):
    if isinstance(dt, datetime):
        return dt.isoformat()  
    return dt

# 날짜 형식이 잘못된 경우 ':'를 '-'로 변환하여 처리
def fix_date_format(date_str):
    try:
        if isinstance(date_str, str):
            if ':' in date_str[:10]:  
                return date_str.replace(':', '-', 2)  
        return date_str  
    except Exception as e:
        raise ValueError(f"Invalid date format: {str(e)}")

# Decimal 타입을 float으로 변환하는 함수
def decimal_to_float(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise obj
