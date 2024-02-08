import uuid
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from fastapi import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.settings import settings
from app.auth.schemas import User, TokenPair, JwtTokenSchema
from app.auth.exceptions import AuthFailedException
from app.db.models import BlackListToken


class JWTAuth:
    def __init__(self):
        self.SUB = "sub"
        self.EXP = "exp"
        self.IAT = "iat"
        self.JTI = "jti"

    def _create_access_token(self, payload: dict, minutes: int | None = None) -> JwtTokenSchema:
        expire = datetime.utcnow() + timedelta(
            minutes=minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
        payload[self.EXP] = expire

        token = JwtTokenSchema(
            token=jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM),
            payload=payload,
            expire=expire,
        )
        return token

    def _create_refresh_token(self, payload: dict) -> JwtTokenSchema:
        expire = datetime.utcnow() + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)

        payload[self.EXP] = expire

        token = JwtTokenSchema(
            token=jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM),
            expires=expire,
            payload=payload,
        )

        return token

    def create_token_pair(self, user: User) -> TokenPair:
        payload = {self.SUB: str(user.id), self.JTI: str(uuid.uuid4()), self.IAT: datetime.utcnow()}
        return TokenPair(
            access=self._create_access_token(payload={**payload}),
            refresh=self._create_access_token(payload={**payload})
        )

    async def decode_access_token(self, token: str, db: AsyncSession):
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            black_list_token = await BlackListToken.find_by_id(db=db, id=payload[self.JTI])
            if black_list_token:
                raise JWTError("Token is blacklisted")
        except JWTError:
            raise AuthFailedException()
        return payload

    def refresh_token_state(self, token: str):
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        except JWTError as ex:
            print(str(ex))
            raise AuthFailedException()
        return {"token": self._create_access_token(payload=payload).token}

    def mail_token(self, user: User):
        payload = {self.SUB: str(user.id), self.JTI: str(uuid.uuid4()), self.IAT: datetime.utcnow()}
        return self._create_access_token(payload=payload, minutes=2 * 60).token

    def add_refresh_token_cookie(self, response: Response, token: str) -> None:
        exp = datetime.utcnow() + timedelta(minutes=settings.RefreshTokenExpiration)
        exp.replace(tzinfo=timezone.utc)
        response.set_cookie(
            key=settings.COOKIE_NAME,
            value=token,
            expires=int(exp.timestamp()),
            httponly=True
        )


jwtauth = JWTAuth()
