import uuid

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, declared_attr
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, AsyncAttrs
from sqlalchemy import select
from fastapi import HTTPException, status


class Base(AsyncAttrs, DeclarativeBase):
    __abstract__ = True

    @declared_attr.directive
    def __tablename__(cls) -> str:
        return f"{cls.__name__.lower()}s"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, index=True, default=uuid.uuid4
    )

    async def save(self, db: AsyncSession):
        try:
            db.add(self)
            return await db.commit()
        except SQLAlchemyError as ex:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=repr(ex)) from ex

    @classmethod
    async def find_by_id(cls, db: AsyncSession, id: str):
        query = select(cls).where(cls.id == id)
        result = await db.execute(query)
        return result.scalar().first()
