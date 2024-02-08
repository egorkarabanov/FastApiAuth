from typing import Any
from datetime import datetime
from pydantic import BaseModel, UUID4, field_validator, EmailStr, validator


class UserBase(BaseModel):
    email: EmailStr
    full_name: str


class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: UUID4

    class Config:
        from_attributes = True

    @field_validator("id")
    def convert_to_str(cls, v, values, **kwargs):
        return str(v) if v else v


class UserRegister(UserBase):
    password: str
    confirm_password: str

    @validator("confirm_password")
    def verify_password_match(cls, v, values, **kwargs):
        password = values.get("password")
        if v != password:
            raise ValueError("Passwords don't match")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class JwtTokenSchema(BaseModel):
    token: str
    payload: dict
    expire: datetime


class TokenPair(BaseModel):
    access: JwtTokenSchema
    refresh: JwtTokenSchema


class RefreshToken(BaseModel):
    refresh: str


class SuccessResponseSchema(BaseModel):
    msg: str


class BlackListToken(BaseModel):
    id: UUID4
    expire: datetime

    class Config:
        from_attributes = True


class MailBodySchema(BaseModel):
    token: str
    type: str


class MailSchema(BaseModel):
    recipient: list[EmailStr]
    subject: str
    body: MailBodySchema


class MailTaskSchema(BaseModel):
    user: User
    body: MailBodySchema


class ForgotPasswordSchema(BaseModel):
    email: EmailStr


class PasswordResetSchema(BaseModel):
    password: str
    confirm_password: str

    @validator("confirm_password")
    def verify_password_match(cls, v, values, **kwargs):
        password = values.get("password")
        if v != password:
            raise ValueError("Passwords don't match")
        return v


class PasswordUpdateSchema(PasswordResetSchema):
    old_password: str


class OldPasswordErrorSchema(BaseModel):
    old_password: bool

    @field_validator("old_password")
    def check_old_password_status(cls, v, values, **kwargs):
        if not v:
            raise ValueError("Old password is not correct")


class ArticleCreateSchema(BaseModel):
    title: str
    content: str


class ArticleListSchema(ArticleCreateSchema):
    id: UUID4
    author_id: UUID4

    class Config:
        from_attributes = True
