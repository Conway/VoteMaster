ORGANIZATION_NAME = '' # Name of organization using this
SITE_NAME = '' # name for this website
VOTE_DESCRIPTION = '' # what type of election/vote is occuring
ORG_HOMEPAGE = '' # the organization's real homepage
END_DATE_STR = '' # date (as a string) that says when the vote ends
DEBUG = False
SECRET_KEY = 'ksdjafasdlkjh2lkj3h2asjdfhdsf' # CHANGEME BEFORE USING
SECURITY_PASSWORD_SALT = 'jsafhasdjghduygi34hdsfagskf' # CHANGEME BEFORE USING

MAX_CHOICES = 2  # the maximum number of choices a voter can choose
EXPOSE_VOTER = True  # allows admins to see all available info about a user on results page
PUBLIC_VALIDATION = False  # allows the public to see results
# allows a user to verify their vote, to be implemented
PUBLIC_VOTE_VERIFICATION = False
# allows a user to see all votes cast, just not who cast them
PUBLIC_TOTAL_RESULTS = False
RANDOMIZE_CHOICES = True  # randomizes order of options

# reCAPTCHA keys
RECAPTCHA_PUBLIC_KEY = ""
RECAPTCHA_PRIVATE_KEY = ""

# Mailgun API
MAILGUN_DOMAIN_NAME = "https://api.mailgun.net/v3/mailgun.domain/messages"
MAILGUN_API_KEY = "key-thisisnotarealmailgunkey"
CONTACT_EMAILS = ['email1@domain.com', 'email2@domain.com]
MAILGUN_DISPLAY_DOMAIN_NAME = "" # domain that emails should come from
