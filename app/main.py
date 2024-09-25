# /app/main.py
from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer
from api.v1 import recommend, model, register, login, auth, mealrecords
from services.auth_service import validate_token
from db.session import get_db
from api.v1.history import router as history_router
from core.logging import logger
from core.middlewares import log_requests
from core.exception_handlers import http_exception_handler, StarletteHTTPException, RequestValidationError, validation_exception_handler

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# 미들웨어 추가
app.middleware("http")(log_requests)

# 예외 처리기 등록
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)

# api 라우터 설정
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth_Verify"])
app.include_router(login.router, prefix="/api/v1/user", tags=["user_Login"])
app.include_router(register.router, prefix="/api/v1/user", tags=["user_Register"])
app.include_router(mealrecords.router, prefix="/api/v1/record", tags=["Meal_Record"], dependencies=[Depends(validate_token)])
app.include_router(recommend.router, prefix="/api/v1/recommend", tags=["Recommend"], dependencies=[Depends(validate_token)])
app.include_router(model.router, prefix="/api/v1/model", tags=["Model"], dependencies=[Depends(validate_token)])
app.include_router(history_router, prefix="/api/v1/history", tags=["History"], dependencies=[Depends(validate_token)])

logger.info("FastAPI application has started.")
