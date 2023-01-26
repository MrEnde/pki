import os
import uuid

from fastapi import Request, HTTPException
from fastapi_utils.inferring_router import InferringRouter
from starlette import status
from streaming_form_data import StreamingFormDataParser
from streaming_form_data.targets import FileTarget, ValueTarget
from streaming_form_data.validators import MaxSizeValidator
import streaming_form_data

from dss_dummy_server.core.file import join_temp_path

router = InferringRouter(prefix="/dss/v1")

MAX_FILE_SIZE = 8 * 1024 * 1024 * 50
MAX_REQUEST_BODY_SIZE = MAX_FILE_SIZE + 1024

ACCEPTED_CONTENT_TYPES = (
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
)

CONTENT_TYPES_TO_FORMAT = {
    "application/pdf": "pdf",
    "application/msword": "doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx"
}

def get_format_file(content_type: str):
    return CONTENT_TYPES_TO_FORMAT[content_type]


@router.post("/upload/")
async def upload_file(request: Request):
    content_type = request.headers.get('content_type')

    if not content_type:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail='Content type header is missing'
        )

    if content_type not in ACCEPTED_CONTENT_TYPES:
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            f"Unsupported media type: {content_type}."
            f"It must be one of {ACCEPTED_CONTENT_TYPES}",
        )

    document_id = str(uuid.uuid4())

    try:
        path = join_temp_path(f"{document_id}.{get_format_file(content_type)}")
        file_target = FileTarget(path.absolute(), validator=MaxSizeValidator(MAX_FILE_SIZE))
        parser = StreamingFormDataParser(headers=request.headers)
        parser.register('file', file_target)

        async for chunk in request.stream():
            parser.data_received(chunk)

    except streaming_form_data.validators.ValidationError:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f'Maximum file size limit ({MAX_FILE_SIZE} bytes) exceeded'
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='There was an error uploading the file'
        )

    if not file_target.multipart_filename:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail='File is missing'
        )

    return {"document_id": document_id}
