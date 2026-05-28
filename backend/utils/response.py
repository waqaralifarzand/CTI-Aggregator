from fastapi.responses import JSONResponse


def ok(data):
    return {"success": True, "data": data, "error": None}


def err(message: str, status_code: int = 400):
    return JSONResponse(
        status_code=status_code,
        content={"success": False, "data": None, "error": message},
    )
