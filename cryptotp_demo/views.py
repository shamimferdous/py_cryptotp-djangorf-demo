from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_406_NOT_ACCEPTABLE
from .utils import send_otp_to_user, send_reset_password_email, activate_user_account

# creating new cryptotp object
from py_cryptotp import Cryptotp
cryototp = Cryptotp(key='16DigitSecretKey')


# send otp endpoint
@api_view(['POST'])
def send_otp(request):

    # generaing a new otp
    otp = cryototp.generate(otp_length=5, otp_duration=2)
    # this is the raw otp eg: 12345 which will be sent to user
    raw_otp = otp.get('raw_otp')
    # this is the hashed_otp eg: lP0zUnCyI1SxUgw with expiration timestamp which will be sent to client as response
    hashed_otp = otp.get('hashed_otp')

    # send the raw_otp to user via SMS/Email
    phone_number = request.data.get('phoneNumber')
    send_otp_to_user(phone_number=phone_number, otp=raw_otp)

    # return the hashed_otp to client
    payload = {
        "hashed_otp": hashed_otp
    }
    return Response(payload, HTTP_200_OK)


# verify otp endpoint
@api_view(['POST'])
def verify_otp(request):

    # destruct hashed otp and user given otp
    user_give_otp = request.data.get('user_otp')
    hashed_otp = request.data.get('hashed_otp')

    # verify otp
    if cryototp.validate(user_given_otp=user_give_otp, hashed_otp=hashed_otp):
        # do further operations accordingly like
        send_reset_password_email()
        activate_user_account()
    else:
        return Response("OTP doesn't match or expired!", HTTP_406_NOT_ACCEPTABLE)

    return Response(HTTP_200_OK)
