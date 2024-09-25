from pydantic import BaseModel



# 토큰 발급을 위한 Pydantic 모델
class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str

# 사용자 정보를 담은 Pydantic 모델
class TokenData(BaseModel):
    user_id: int = None
    
# 요청 바디 스키마 정의
class TokenRequest(BaseModel):
    refresh_token: str

