def ok(data):
    return {"success": True, "data": data, "error": None}


def err(message: str):
    return {"success": False, "data": None, "error": message}
