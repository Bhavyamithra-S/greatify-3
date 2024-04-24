import base64

from rest_framework import views
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework import status
from rest_framework.response import Response
from .serializers import *
from .emails import EmailService
from django.contrib.auth import logout, login


class SignupView(views.APIView):

    permission_classes = (AllowAny,)

    def post(self, request):
        try:
            data = request.data
            try:
                user = User.objects.get(email=data['email'])
                return Response(data={'status': 'failed'}, status=status.HTTP_404_NOT_FOUND)
            except User.DoesNotExist:
                all_user = User.objects.filter(username=data.username)
                if all_user:
                    return Response(data={'status': "failed"}, status=status.HTTP_409_CONFLICT)
                serializer = CreateUserSerializer(data=data)
                if serializer.is_valid():
                    serializer.save()
                    user = User.objects.get(email=serializer.data['email'])
                    password = base64.b64decode(data['password']).decode('ascii')
                    user.set_password(password)
                    user.save()
                    return Response(data={'status': "success"}, status=status.HTTP_200_OK)
                else:
                    return Response(data={'status': 'failed',
                                          'error_msg': serializer.errors}, status=status.HTTP_406_NOT_ACCEPTABLE)
        except Exception as e:
            print("Sign up data: " + str(request.data) + str(e))
            return Response(data={'status': "failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginView(views.APIView):
    """
    Login View allows the user to login into the application
    """
    permission_classes = (AllowAny,)

    def post(self, request):
        try:

            data = request.data
            try:
                user = User.objects.get(username=data['username'])
            except User.DoesNotExist:
                return Response(data={'status': 'failed'}, status=status.HTTP_404_NOT_FOUND)
            validate_user = LoginSerializer(data=data)
            if validate_user.is_valid():
                user = validate_user.validated_data
                login(request, user)
                return Response(data={'status': "success"}, status=status.HTTP_200_OK)
            else:
                return Response(data={'status': 'failed',
                                      'error_msg': validate_user.errors}, status=status.HTTP_406_NOT_ACCEPTABLE)
        except Exception as e:
            print("Login data: " + str(request.data) + str(e))
            return Response(data={'status': "failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasswordResetEmailView(views.APIView):
    permission_classes = (AllowAny,)

    def get(self, request):
        try:
            data = request.data
            email = data.get('email', None)
            if not email:
                return Response(data={'status': 'failed'}, status=status.HTTP_400_BAD_REQUEST)
            try:
                user = User.objects.get(email=email)
                EmailService.send_email({"email": user.email})
                return Response(data={'status': "success"}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response(data={'status': 'failed'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print("Reset User Password Mail :" + str(e))
            return Response(data={'status': "failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            data = request.data
            email = data.get('email', None)
            password = data.get('password', None)
            if not email or not password:
                return Response(data={'status': 'failed'}, status=status.HTTP_400_BAD_REQUEST)
            password = base64.b64decode(password).decode('ascii')
            try:
                user = User.objects.get(email=email)
                user.set_password(password)
                user.save()
                return Response(data={'status': "success"}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response(data={'status': 'failed'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print("Reset User Password: " + str(e))
            return Response(data={'status': "failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ProfileView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            try:
                return Response(data={'status': "success",
                                      "user_details": {"username": user.username,
                                                       "email": user.email,
                                                       "mobile": user.mobile_number,
                                                       "job_title": user.job_title,
                                                       "role": user.role}}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response(data={'status': 'failed'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print("Reset User Password Mail :" + str(e))
            return Response(data={'status': "failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request):
        try:
            data = request.data
            try:
                user = request.user
                if data['username']:
                    all_user = User.objects.filter(username=data['username'])
                    if all_user:
                        return Response(data={'status': "failed"}, status=status.HTTP_409_CONFLICT)
                serializer = ProfileEditSerializer(data=data)
                if serializer.is_valid():
                    serializer.save()
                    if data['password']:
                        user = User.objects.get(email=serializer.data['email'])
                        password = base64.b64decode(data['password']).decode('ascii')
                        user.set_password(password)
                        user.save()
                    return Response(data={'status': "success"}, status=status.HTTP_200_OK)
                else:
                    return Response(data={'status': 'failed',
                                          'error_msg': serializer.errors}, status=status.HTTP_406_NOT_ACCEPTABLE)
            except User.DoesNotExist:
                return Response(data={'status': 'failed'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print("Reset User Password: " + str(e))
            return Response(data={'status': "failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserListView(views.APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        try:
            user = request.user
            if user.role == 'admin':
                all_user = User.objects.all()
                serializer = CreateUserSerializer(data=all_user, many=True)
                return Response(data={'status': "success",
                                      'data': serializer.data}, status=status.HTTP_200_OK)
            else:
                return Response(data={'status': 'failed'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print("Reset User Password Mail :" + str(e))
            return Response(data={'status': "failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(views.APIView):
    """
    Login View allows the user to login into the application
    """
    permission_classes = (AllowAny,)

    def delete(self, request):
        try:
            logout(request)
            return Response(data={'status': "success"}, status=status.HTTP_200_OK)
        except Exception as e:
            print("Login data: " + str(request.data) + str(e))
            return Response(data={'status': "failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

