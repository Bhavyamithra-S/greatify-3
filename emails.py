from django.core.mail import EmailMultiAlternatives


class EmailService(object):

    @staticmethod
    def send_email(data):
        try:
            mail = EmailMultiAlternatives("User-Auth: Password Reset Email", None,
                                          "bmithra0103@gmail.com", [data['email']])
            url = ""
            html_message = EmailConstant.PASSWORD_RESET.format(
                url=url,
            )
            if html_message:
                mail.attach_alternative(html_message, 'text/html')
            mail.send()

        except Exception as e:
            print("Password reset Email" + str(data['email']) + str(e))


class EmailConstant(object):
    PASSWORD_RESET = """<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Password Reset</title>
        </head>
        <body style="text-align: center">
            <p>You have requested a password reset. Please click the link below to reset your password:</p>
            <p><a href="{url}">Reset Password</a></p>
            <p>If you did not request a password reset, please ignore this email.</p>
        </body>
        </html>"""