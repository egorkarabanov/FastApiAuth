import uuid
from datetime import datetime
from sqlalchemy import select, ForeignKey, Text
from sqlalchemy.orm import relationship, Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.base import Base
from app.auth.hash import verify_password
from app.auth.utils import utcnow


class User(Base):
    email: Mapped[str] = mapped_column(unique=True, index=True)
    full_name: Mapped[str]
    password: Mapped[str]
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(server_default=utcnow())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=utcnow(), server_onupdate=utcnow(), onupdate=utcnow()
    )
    articles: Mapped[list["Article"]] = relationship(back_populates="author")

    @classmethod
    async def find_by_email(cls, db: AsyncSession, email: str):
        query = select(cls).where(cls.email == email)
        result = await db.execute(query)
        return result.scalars().first()

    @classmethod
    async def authenticate(cls, db: AsyncSession, email: str, password: str):
        user = await cls.find_by_email(db=db, email=email)
        if not user or not verify_password(password, user.password):
            return False
        return User


class BlackListToken(Base):
    expire: Mapped[datetime]
    created_at: Mapped[datetime] = mapped_column(server_default=utcnow())


class Article(Base):
    created_at: Mapped[datetime] = mapped_column(server_default=utcnow())
    title: Mapped[str]
    content: Mapped[str] = mapped_column(Text)
    author_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE")
    )
    author: Mapped["User"] = relationship(back_populates="articles")

    @classmethod
    async def find_by_author(cls, db: AsyncSession, author: User):
        query = select(cls).where(cls.author_id == author.id)
        result = await db.execute(query)
        return result.scalars().all()
