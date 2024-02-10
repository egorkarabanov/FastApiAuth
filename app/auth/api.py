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
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


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


@router.post("/login")
async def login(
        data: schemas.UserLogin,
        response: Response,
        db: AsyncSession = Depends(db_helper.get_scoped_session)
):
    user = await models.User.authenticate(
        db=db, email=data.email, password=data.password
    )

    if not user:
        raise BadRequestException(detail="Incorrect email or password")
    if not user.is_active:
        raise ForbiddenException()

    user = schemas.User.model_validate(user)
    token_pair = jwtauth.create_token_pair(user=user)
    jwtauth.add_refresh_token_cookie(response=response, token=token_pair.refresh.token)
    return {"token": token_pair.access.token}


@router.post("/refresh")
async def refresh(refresh: Annotated[str | None, Cookie()] = None):
    if not refresh:
        raise BadRequestException(detail="Refresh token is required")
    return jwtauth.refresh_token_state(token=refresh)


@router.get("/verify", response_model=schemas.SuccessResponseSchema)
async def verify(token: str, db: AsyncSession = Depends(db_helper.get_scoped_session)):
    payload = await jwtauth.decode_access_token(token, db)
    user = await models.User.find_by_id(db, id=payload["id"])
    if not user:
        raise NotFoundException(detail="User not found")
    user.is_active = True
    await user.save(db=db)
    return {"msg": "User verified"}


@router.post("/logout", response_model=schemas.SuccessResponseSchema)
async def logout(
        token: Annotated[str, Depends(oauth2_scheme)],
        db: AsyncSession = Depends(db_helper.get_scoped_session)
):
    payload = await jwtauth.decode_access_token(token, db)
    black_listed = models.BlackListToken(
        id=payload[jwtauth.JTI], expire=datetime.utcfromtimestamp(payload[jwtauth.EXP])
    )
    await black_listed.save(db=db)
    return {"msg": "Successfully logout"}


@router.post("/forgot-password", response_model=schemas.SuccessResponseSchema)
async def forgot_password(
        data: schemas.ForgotPasswordSchema,
        bg_task: BackgroundTasks,
        db: AsyncSession = Depends(db_helper.get_scoped_session)
):
    user = await models.User.find_by_email(db, email=data.email)
    if user:
        user_schema = schemas.User.model_validate(user)
        reset_token = jwtauth.mail_token(user_schema)
        mail_task_data = schemas.MailTaskSchema(
            user=user_schema,
            body=schemas.MailBodySchema(type='password-reset', token=reset_token)
        )
        bg_task.add_task(user_mail_event, mail_task_data)

    return {"msg": "Reset token sended successfully your email check your email"}


@router.post("/password-reset", response_model=schemas.SuccessResponseSchema)
async def password_reset_token(
        token: str,
        data: schemas.PasswordResetSchema,
        db: AsyncSession = Depends(db_helper.get_scoped_session)
):
    payload = await jwtauth.decode_access_token(token, db)
    user = await models.User.find_by_id(db=db, id=payload[jwtauth.SUB])
    if not user:
        raise NotFoundException(detail="User not found")

    user.password = get_password_hash(data.password)
    await user.save(db)
    return {"msg": "Password successfully updated"}


@router.post("/password-update", response_model=schemas.SuccessResponseSchema)
async def password_update(
        token: Annotated[str, Depends(oauth2_scheme)],
        data: schemas.PasswordUpdateSchema,
        db: AsyncSession = Depends(db_helper.get_scoped_session)
):
    payload = await jwtauth.decode_access_token(token, db)
    user = await models.User.find_by_id(db=db, id=payload[jwtauth.SUB])
    if not user:
        raise NotFoundException(detail="User not found")
    if not verify_password(data.old_password, user.password):
        try:
            schemas.OldPasswordErrorSchema(old_password=False)
        except ValidationError as e:
            raise RequestValidationError(e.raw_errors)
    user.password = get_password_hash(data.password)
    await user.save(db)
    return {"msg": "Password successfully updated"}


@router.get("/articles")
async def articles(
        token: Annotated[str, Depends(oauth2_scheme)],
        db: AsyncSession = Depends(db_helper.get_scoped_session)
):
    payload = await jwtauth.decode_access_token(token, db)
    user = await models.User.find_by_id(db, id=payload[jwtauth.SUB])
    if not user:
        raise NotFoundException(detail="User not found")
    articles = await models.Article.find_by_author(db=db, author=user)
    return [schemas.ArticleListSchema.model_validate(article) for article in articles]


@router.post("/articles", response_model=schemas.SuccessResponseSchema, status_code=201)
async def create_article(
        token: Annotated[str, Depends(oauth2_scheme)],
        data: schemas.ArticleCreateSchema,
        db: AsyncSession = Depends(db_helper.get_scoped_session)
):
    payload = await jwtauth.decode_access_token(token, db)
    user = await models.User.find_by_id(db, id=payload[jwtauth.SUB])
    if not user:
        raise NotFoundException(detail="User not found")
    article = models.Article(**data.dict())
    article.author = user

    await article.save(db=db)
    return {"msg": "Successfully created article"}
