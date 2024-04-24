from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.test import APITestCase
from unittest.mock import patch
from emails import EmailService
from rest_framework.authtoken.models import Token


class SignupViewTests(APITestCase):
    def setUp(self):
        self.signup_url = 'signup/'

    def test_successful_signup(self):
        data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpassword'
        }
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'success')

    def test_signup_with_existing_email(self):
        User.objects.create_user(username='existinguser', email='existing@example.com', password='existingpassword')
        data = {
            'username': 'newuser',
            'email': 'existing@example.com',  # Using existing email
            'password': 'newpassword'
        }
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['status'], 'failed')

    def test_signup_with_existing_username(self):
        User.objects.create_user(username='existinguser', email='existing@example.com', password='existingpassword')
        data = {
            'username': 'existinguser',  # Using existing username
            'email': 'new@example.com',
            'password': 'newpassword'
        }
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.data['status'], 'failed')

    def test_invalid_data_signup(self):
        data = {
            'username': '',  # Invalid data
            'email': 'test@example.com',
            'password': 'testpassword'
        }
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_406_NOT_ACCEPTABLE)
        self.assertEqual(response.data['status'], 'failed')

    def test_internal_server_error(self):
        # Simulate internal server error by passing invalid data
        data = {
            'invalid_key': 'test',
        }
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data['status'], 'failed')


class LoginViewTests(APITestCase):
    def setUp(self):
        self.login_url = 'login/'
        self.user = User.objects.create_user(username='testuser', email='test@example.com', password='testpassword')

    def test_successful_login(self):
        data = {
            'username': 'testuser',
            'password': 'testpassword'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'success')

    def test_invalid_credentials_login(self):
        data = {
            'username': 'testuser',
            'password': 'wrongpassword'  # Invalid password
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['status'], 'failed')

    def test_user_not_found_login(self):
        data = {
            'username': 'nonexistentuser',  # User does not exist
            'password': 'testpassword'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['status'], 'failed')

    def test_internal_server_error(self):
        # Simulate internal server error by passing invalid data
        data = {
            'invalid_key': 'test',
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data['status'], 'failed')


class PasswordResetEmailViewTests(APITestCase):
    def setUp(self):
        self.password_reset_url = 'password-reset/'

    @patch.object(EmailService, 'send_email')
    def test_successful_password_reset_email(self, mock_send_email):
        user = User.objects.create_user(username='testuser', email='test@example.com', password='testpassword')
        data = {'email': 'test@example.com'}
        response = self.client.get(self.password_reset_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'success')
        mock_send_email.assert_called_once_with({'email': user.email})

    def test_missing_email_password_reset_email(self):
        data = {}  # Missing email
        response = self.client.get(self.password_reset_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], 'failed')

    def test_invalid_email_password_reset_email(self):
        data = {'email': 'invalidemail@example.com'}  # Invalid email
        response = self.client.get(self.password_reset_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['status'], 'failed')

    def test_successful_password_reset(self):
        user = User.objects.create_user(username='testuser', email='test@example.com', password='testpassword')
        new_password = 'newpassword'
        data = {'email': 'test@example.com', 'password': new_password}
        response = self.client.post(self.password_reset_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'success')
        user.refresh_from_db()  # Refresh user instance from database
        self.assertTrue(user.check_password(new_password))

    def test_missing_email_or_password_password_reset(self):
        data = {'email': 'test@example.com'}  # Missing password
        response = self.client.post(self.password_reset_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['status'], 'failed')

    def test_invalid_email_password_reset(self):
        data = {'email': 'invalidemail@example.com', 'password': 'newpassword'}  # Invalid email
        response = self.client.post(self.password_reset_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['status'], 'failed')


class ProfileViewTests(APITestCase):
    def setUp(self):
        self.profile_url = 'profile/'

    def test_get_profile(self):
        user = User.objects.create_user(username='testuser', email='test@example.com', password='testpassword')
        token = Token.objects.create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'success')
        self.assertEqual(response.data['user_details']['username'], 'testuser')

    def test_put_profile(self):
        user = User.objects.create_user(username='testuser', email='test@example.com', password='testpassword')
        token = Token.objects.create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        data = {
            'username': 'updatedusername',
            'password': 'newpassword'
        }
        response = self.client.put(self.profile_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'success')
        user.refresh_from_db()
        self.assertEqual(user.username, 'updatedusername')
        self.assertTrue(user.check_password('newpassword'))


class UserListViewTests(APITestCase):
    def setUp(self):
        self.user_list_url = 'user-list/'

    def test_get_user_list_as_admin(self):
        admin_user = User.objects.create_superuser(username='adminuser', email='admin@example.com', password='adminpassword')
        admin_token = Token.objects.create(user=admin_user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {admin_token.key}')
        response = self.client.get(self.user_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'success')

    def test_get_user_list_as_non_admin(self):
        user = User.objects.create_user(username='testuser', email='test@example.com', password='testpassword')
        token = Token.objects.create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        response = self.client.get(self.user_list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class LogoutViewTests(APITestCase):
    def setUp(self):
        self.logout_url = 'logout/'

    def test_logout(self):
        user = User.objects.create_user(username='testuser', email='test@example.com', password='testpassword')
        token = Token.objects.create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        response = self.client.delete(self.logout_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'success')