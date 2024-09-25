import asyncio
from datetime import datetime, timedelta
import pytz
import aioboto3
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from db import crud
from db.crud import get_daily_logs, delete_old_logs
from db.session import async_session
from core.logging import logger
from core.config import BUCKET_NAME

async def generate_daily_log():
    aws_session = aioboto3.Session()    

    while True:
        try:
            korea_timezone = pytz.timezone('Asia/Seoul')
            now = datetime.now(korea_timezone)
            yesterday = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)

            # 한국 시간을 UTC로 변환
            yesterday_utc = yesterday.astimezone(pytz.utc)

            async with async_session() as session:
                logs = await crud.get_daily_logs(session, yesterday_utc)

                filename = fr"C:\Users\Playdata\backend\Fastapi-backend\Wellnessapp\app\dailylogtxt\{yesterday.strftime('%Y-%m-%d')}-errors.txt"
                try:
                    with open(filename, 'w', encoding='utf-8') as f:
                        for log in logs:
                            # 로그의 타임스탬프를 한국 시간으로 변환
                            log_time_korea = log.time_stamp.astimezone(korea_timezone)
                            f.write(f"{log_time_korea}: {log.method} {log.req_url} - {log.code}\n")

                    logger.info(f"Log file {filename} created successfully.")
            
                    # S3 업로드 추후 진행
                    # async with session.client('s3') as s3:
                    #     await s3.upload_file(filename, bucket_name, f"logs/{filename}")
                    # logger.info(f"Log file {filename} uploaded to S3 successfully.")

                except IOError as e:
                    logger.error(f"Error writing to file {filename}: {e}")
                except Exception as e:
                    logger.error(f"Error uploading to S3: {e}")

            try:
                await crud.delete_old_logs(session, 30)
                logger.info("Old logs deleted successfully.")
            except Exception as e:
                logger.error(f"Error deleting old logs: {e}")

            # 다음 날 대기
            tomorrow = (now + timedelta(hours=12)).replace(hour=0, minute=0, second=0, microsecond=0)
            wait_time = (tomorrow - now).total_seconds()
            logger.info(f"Waiting for {wait_time} seconds until next execution.")
            await asyncio.sleep(wait_time)

        except Exception as e:
            logger.error(f"Unexpected error in generate_daily_log: {e}")
            await asyncio.sleep(60)  # 오류 발생 시 1분 후 재시도

if __name__ == "__main__":
    asyncio.run(generate_daily_log())
    