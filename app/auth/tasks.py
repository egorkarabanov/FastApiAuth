from app.auth.schemas import MailTaskSchema


def user_mail_event(payload: MailTaskSchema):
    print(f"[Mail Schema]: {payload}")
