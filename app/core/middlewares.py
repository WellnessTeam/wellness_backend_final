import time
from fastapi import Request
from fastapi.responses import Response
from datetime import datetime
from core.logging import logger
from db.crud import create_log
from schemas.log import LogCreate
from sqlalchemy.ext.asyncio import AsyncSession
from db.session import engine
import pytz

KST = pytz.timezone('Asia/Seoul')

# 요청 및 응답을 기록하는 미들웨어
async def log_requests(request: Request, call_next):
    logger.info(f"Incoming request: {request.method} {request.url}")
    req_param = str(request.query_params)
    start_time = time.time()

    response = await call_next(request)

    response_body = b""
    async for chunk in response.body_iterator:
        response_body += chunk

    duration = time.time() - start_time
    logger.info(f"Completed request in {duration:.2f}s - Status Code: {response.status_code}")

    log_entry = LogCreate(
        req_url=str(request.url),
        method=request.method,
        req_param=req_param,
        res_param=response_body.decode(),
        msg="Request completed",
        code=response.status_code,
        time_stamp=datetime.now(KST)
    )

    async with AsyncSession(engine) as db:
        await create_log(db, log_entry)

    return Response(content=response_body, status_code=response.status_code, 
                    headers=dict(response.headers), media_type=response.media_type)
