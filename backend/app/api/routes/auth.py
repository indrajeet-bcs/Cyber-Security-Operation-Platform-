from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login")
async def login():
    return {"message": "Login endpoint"}


@router.post("/logout")
async def logout():
    return {"message": "Logout endpoint"}
