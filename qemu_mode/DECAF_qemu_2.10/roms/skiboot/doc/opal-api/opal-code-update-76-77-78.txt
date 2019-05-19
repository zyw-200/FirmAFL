Code Update on FSP based machine
================================

There are three OPAL calls for code update on FSP based machine:

 #define OPAL_FLASH_VALIDATE	76
 #define OPAL_FLASH_MANAGE	77
 #define OPAL_FLASH_UPDATE	78

OPAL_FLASH_VALIDATE
-------------------
  Validate new image is valid for this platform or not. We do below
  validation in OPAL:
   - We do below sys parameters validation to confirm inband
     update is allowed.
     - Platform is managed by HMC or not?.
     - Code update policy (inband code update allowed?).

   - We parse candidate image header (first 4k bytes) to perform
     below validations.
     - Image magic number.
     - Image version to confirm image is valid for this platform.

  Input:
    buffer	: First 4k bytes of new image
    size	: Input buffer size

  Output:
    buffer	: Output result (current and new image version details)
    size	: Output buffer size
    result	: Token to identify what will happen if update is attempted
		  See hw/fsp/fsp-codeupdate.h for token values.

  Return value:
    Validation status


OPAL_FLASH_MANAGE
-----------------
  Commit/Reject image.
    - We can commit new image (T -> P), if system is running with T side image.
    - We can reject T side image, if system is running with P side image.

    Note:
       If a platform is running from a T side image when an update is to be
       applied, then the platform may automatically commit the current T side
       image to the P side to allow the new image to be updated to the
       temporary image area.

  Input
     op	: Operation (1 : Commit /0 : Reject)

  Return value:
    Commit operation status (0 : Success)

OPAL_FLASH_UPDATE
------------------
  Update new image. It only sets the flag, actual update happens
  during system reboot/shutdown.

  Host splits FW image to scatter/gather list and sends it to OPAL.
  OPAL parse the image to get indivisual LID and passes it to FSP
  via MBOX command.

  FW update flow :
    - if (running side == T)
        Swap P & T side
    - Start code update
    - Delete T side LIDs
    - Write LIDs
    - Code update complete
    - Deep IPL

  Input
    list  : Real address of image scatter/gather list of the FW image

  Return value:
    Update operation status (0: update requested)
