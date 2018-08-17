# Copyright 2018 haidd
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

from odoo import api, fields, models
from odoo.exceptions import ValidationError


class PasswordManagerWizard(models.TransientModel):
    _name = 'password.manager.wizard'

    password_manager_id = fields.Many2one(
        'password.manager', string="User Name")
    password = fields.Char()
    type = fields.Selection(
        [("login", "login"), ("change_pass", "change_pass")],
        default="login",
    )

    @api.multi
    def button_test_login(self):
        self.ensure_one()
        password_manager = self.password_manager_id
        encrypted = password_manager.password_crypt
        valid_pass, replacement = password_manager._crypt_context()\
            .verify_and_update(self.password, encrypted)
        if not valid_pass:
            raise ValidationError('Invalid password')
        return {'type': 'ir.actions.act_window_close'}

    @api.multi
    def button_change_password(self):
        self.ensure_one()
        password_manager = self.password_manager_id
        password_manager.password = self.password
        return {'type': 'ir.actions.act_window_close'}
