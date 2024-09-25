# /app/utils/image_processing.py
from PIL import Image, ExifTags, UnidentifiedImageError
from io import BytesIO
import datetime
from fastapi import HTTPException, status

def extract_exif_data(file_bytes: bytes):
    try:
        img = Image.open(BytesIO(file_bytes))
        exif_data = img._getexif()
        
        if not exif_data:
            return None
        
        for tag, value in exif_data.items():
            decoded_tag = ExifTags.TAGS.get(tag, tag)
            if decoded_tag == "DateTimeOriginal":
                return value  
        return None 
    
    except UnidentifiedImageError:
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail={
                "status": "ForBidden",
                "status_code": "403",
                "detail": "invalid image format."
            }
        )
    
    except AttributeError:
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "status": "ForBidden",
                "status_code": "403",
                "detail": f"Error: {str(e)}"
            }
        )
        
def format_date(date_str: str) -> str:
    """받은 날짜 문자열을 YYYY-MM-DD HH:MM:SS 형식으로 변환합니다."""
    try:
        # EXIF 데이터에서 가져온 형식은 "YYYY:MM:DD HH:MM:SS"이므로 변환합니다.
        if isinstance(date_str, str):
            date_str = date_str.replace(':', '-')  # ':'를 '-'로 변경
            date_obj = datetime.datetime.strptime(date_str, "%Y-%m-%d %H-%M-%S")
            return date_obj.strftime("%Y-%m-%d %H:%M:%S")  # 원하는 형식으로 반환
    except Exception as e:
        raise ValueError(f"Invalid date format: {str(e)}")

def determine_meal_type(taken_time: str) -> str:
    try:
        time_format = "%Y:%m:%d %H:%M:%S"
        
        # Exif 데이터가 없으면 현재 시간을 사용
        if isinstance(taken_time, str):
            taken_time_obj = datetime.datetime.strptime(taken_time, time_format)  # 문자열을 datetime 객체로 변환
        else:
            taken_time_obj = datetime.datetime.now()  # Exif 데이터가 없을 경우 현재 서버 시간을 사용
        
        # 여기에서 더 이상 datetime 변환을 하지 않음
        hour = taken_time_obj.hour
        
        # 시간대에 따라 아침, 점심, 저녁, 기타를 반환
        if 6 <= hour <= 8:
            return "아침"
        elif 11 <= hour <= 13:
            return "점심"
        elif 17 <= hour <= 19:
            return "저녁"
        else:
            return "기타"

        
    except ValueError as e:
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "status": "Bad Request",
                "status_code": "400",
                "detail": f"Invalid datetime format: {str(e)}"
            }
        )
    except Exception as e:
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "status": "Bad Request",
                "status_code": "400",
                "detail": f"Error: {str(e)}"
            }
        )