"""OCSP responder routes"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session
from typing import Optional

from atr.core.db import get_db
from atr.ocsp.responder import OCSPResponder

router = APIRouter(prefix="/ocsp", tags=["ocsp"])


@router.post("", response_class=Response)
async def ocsp_responder(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    OCSP responder endpoint.
    
    Accepts POST requests with DER-encoded OCSP requests.
    Returns DER-encoded OCSP responses.
    
    Note: This is a simplified implementation for POC.
    In production, you'd want:
    - Proper request parsing
    - Response signing
    - Caching
    - Nonce handling
    """
    try:
        # Get request body (DER-encoded OCSP request)
        ocsp_request_bytes = await request.body()
        
        # Process request
        responder = OCSPResponder(db)
        ocsp_response_bytes = responder.process_request(ocsp_request_bytes)
        
        if ocsp_response_bytes:
            return Response(
                content=ocsp_response_bytes,
                media_type="application/ocsp-response"
            )
        else:
            # Return error response
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid OCSP request or not yet fully implemented"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"OCSP processing error: {str(e)}"
        )


@router.get("/status/{serial_number}")
def get_certificate_status(
    serial_number: str,
    db: Session = Depends(get_db)
):
    """
    Get certificate status by serial number (for testing/debugging).
    
    This is a REST API endpoint for checking certificate status,
    useful for debugging and testing. Real OCSP clients would use
    the POST /ocsp endpoint.
    """
    from atr.pki.ca import get_ca
    
    ca = get_ca()
    issuer_name = ca.get_intermediate_cert().subject
    
    responder = OCSPResponder(db)
    status_info = responder.get_certificate_status_by_serial(
        serial_number,
        issuer_name
    )
    
    return {
        "serial_number": serial_number,
        "status": status_info["status"],
        "revocation_time": status_info["revocation_time"].isoformat() if status_info["revocation_time"] else None,
        "revocation_reason": status_info["revocation_reason"]
    }
