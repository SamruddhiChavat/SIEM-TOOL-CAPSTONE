import asyncio
import os
import sys
import uuid

# add parent directory to path
sys.path.insert(0, os.path.dirname(__file__))

from db.database import async_session
from db.models import User
from auth.jwt_handler import get_password_hash
from sqlalchemy.future import select

async def main():
    username = os.getenv("ADMIN_USER", "admin")
    password = os.getenv("ADMIN_PASS", "SecureWatch123!")

    async with async_session() as session:
        result = await session.execute(select(User).where(User.username == username))
        existing_user = result.scalars().first()

        if existing_user:
            print(f"User {username} already exists.")
            return

        print(f"Creating admin user: {username}")
        new_user = User(
            id=str(uuid.uuid4()),
            username=username,
            hashed_password=get_password_hash(password),
            role="admin",
            is_active=True
        )

        session.add(new_user)
        await session.commit()
        print("Admin user created successfully.")

if __name__ == "__main__":
    asyncio.run(main())
