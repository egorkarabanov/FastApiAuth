from typing import Annotated
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, status, Response, Cookie
from fastapi.exceptions import RequestValidationError
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import ValidationError
from app.db.db_helper import db_helper
import app.auth.schemas as schemas
import app.db.models as models
from app.auth.hash import get_password_hash, verify_password
from app.auth.jwt import jwtauth
from app.auth.exceptions import BadRequestException, NotFoundException, ForbiddenException
from app.auth.tasks import user_mail_event

router = APIRouter(prefix="/auth")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@router.post("/register", response_model=schemas.User)
async def register(
        data: schemas.UserRegister,
        bg_task: BackgroundTasks,
        db: AsyncSession = Depends(db_helper.get_scoped_session)
):
    user = await models.User.find_by_email(db=db, email=data.email)
    if user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email has already registered")

    user_data = data.dict(exclude={"confirm_password"})
    user_data["password"] = get_password_hash(user_data["password"])

    user = models.User(**user_data)
    await user.save(db=db)

    user_schema = schemas.User.model_validate(user)
    verify_token = jwtauth.mail_token(user_schema)

    mail_task_data = schemas.MailTaskSchema(
        user=user_schema, body=schemas.MailBodySchema(type="verify", token=verify_token)
    )
    bg_task.add_task(user_mail_event, mail_task_data)

    return user_schema
