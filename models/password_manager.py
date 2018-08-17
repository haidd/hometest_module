# Copyright 2018 haidd
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import re
from passlib.context import CryptContext
from string import ascii_uppercase, ascii_lowercase, digits

from odoo import api, fields, models
from odoo.exceptions import AccessDenied, ValidationError


def contains(required_chars, s):
    return any(c in required_chars for c in s)


def contains_upper(s):
    return contains(ascii_uppercase, s)


def contains_lower(s):
    return contains(ascii_lowercase, s)


def contains_digit(s):
    return contains(digits, s)


def contains_special(s):
    return contains(r"""!@$%^&*()_-+={}[]|\,.></?~`"':;""", s)


def not_contains_whitespace(s):
    return not contains(' ', s)


def long_enough(s):
    return len(s) >= 6


def validate_password(password):
    # Based on https://codereview.stackexchange.com/questions/165187/password-checker-in-python
    VALIDATIONS = (
        (contains_upper, '- Password needs at least one upper-case character.\n'),
        (contains_lower, '- Password needs at least one lower-case character.\n'),
        (contains_digit, '- Password needs at least one number.'),
        (contains_special, '- Password needs at least one special character.\n'),
        (not_contains_whitespace, '- Password must not contain any whitespace.\n'),
        (long_enough, '- Password needs to be at least 6 characters in length.\n'),
    )
    message = ""
    failures = [
        msg for validator, msg in VALIDATIONS if not validator(password)
    ]
    if not failures:
        return message
    else:
        message = "Invalid password! Review below and change your password accordingly!\n"
        for msg in failures:
            message += msg
        return message


default_crypt_context = CryptContext(
    # kdf which can be verified by the context. The default encryption kdf is
    # the first of the list
    ['pbkdf2_sha512', 'md5_crypt'],
    # deprecated algorithms are still verified as usual, but ``needs_update``
    # will indicate that the stored hash should be replaced by a more recent
    # algorithm. Passlib 1.6 supports an `auto` value which deprecates any
    # algorithm but the default, but Ubuntu LTS only provides 1.5 so far.
    deprecated=['md5_crypt'],
)


class PasswordManager(models.Model):
    _name = 'password.manager'
    _description = '''Manage passwords for the system'''

    name = fields.Char('User name')
    password = fields.Char()
    password_crypt = fields.Char(
        string='Encrypted Password',
        invisible=True,
        copy=False
    )
    is_crypt = fields.Boolean()

    @api.multi
    def set_password(self):
        for record in self:
            record._set_password(record.password)
            self.invalidate_cache()

    def _set_password(self, password):
        self.ensure_one()
        """ Encrypts then stores the provided plaintext password for the user
        ``self``
        """
        encrypted = self._crypt_context().encrypt(password)
        self._set_encrypted_password(encrypted)

    def _set_encrypted_password(self, encrypted):
        """ Store the provided encrypted password to the database, and clears
        any plaintext password
        """
        self.env.cr.execute(
            "UPDATE password_manager SET password='', password_crypt=%s WHERE id=%s",
            (encrypted, self.id))

    def _crypt_context(self):
        """ Passlib CryptContext instance used to encrypt and verify
        passwords. Can be overridden if technical, legal or political matters
        require different kdfs than the provided default.

        Requires a CryptContext as deprecation and upgrade notices are used
        internally
        """
        return default_crypt_context

    def check_password(self, password):
        return validate_password(password)

    @api.model
    def create(self, vals):
        if 'password' in vals:
            password = vals.get('password', '')
            mess = self.check_password(password)
            if mess:
                raise ValidationError(mess)
        vals.update({'is_crypt': True})
        res = super(PasswordManager, self).create(vals)
        res.set_password()
        return res

    @api.multi
    def write(self, vals):
        if 'password' in vals:
            password = vals.get('password', '')
            mess = self.check_password(password)
            if mess:
                raise ValidationError(mess)
        res = super(PasswordManager, self).write(vals)
        self.set_password()
        return res

    @api.multi
    def button_test_login(self):
        self.ensure_one()
        wiz = self.env['password.manager.wizard'].create({
            'password_manager_id': self.id,
            'type': 'login'
        })
        return {
            'name': 'Test Login',
            'type': 'ir.actions.act_window',
            'view_type': 'form',
            'view_mode': 'form',
            'view_id':
            self.env.ref('hometest_module.password_manager_wizard_form').id,
            'res_model': 'password.manager.wizard',
            'target': 'new',
            'res_id': wiz.id,
            'context': self.env.context,
        }

    @api.multi
    def button_change_password(self):
        self.ensure_one()
        wiz = self.env['password.manager.wizard'].create({
            'password_manager_id': self.id,
            'type': 'change_pass',
        })
        return {
            'name': 'Change Password',
            'type': 'ir.actions.act_window',
            'view_type': 'form',
            'view_mode': 'form',
            'view_id':
            self.env.ref('hometest_module.password_manager_wizard_form').id,
            'res_model': 'password.manager.wizard',
            'target': 'new',
            'res_id': wiz.id,
            'context': self.env.context,
        }
