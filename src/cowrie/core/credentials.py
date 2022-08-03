# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from __future__ import annotations

from typing import Callable

from zope.interface import implementer

from twisted.cred.credentials import ICredentials, IUsernamePassword

from twisted.python import log
from cowrie.core.config import CowrieConfig
import hashlib
from collections import OrderedDict
from typing import Any, Pattern, Union
import re

class IUsername(ICredentials):
    """
    Encapsulate username only

    @type username: C{str}
    @ivar username: The username associated with these credentials.
    """


class IUsernamePasswordIP(IUsernamePassword):
    """
    I encapsulate a username, a plaintext password and a source IP

    @type username: C{str}
    @ivar username: The username associated with these credentials.

    @type password: C{str}
    @ivar password: The password associated with these credentials.

    @type ip: C{str}
    @ivar ip: The source ip address associated with these credentials.
    """


class IPluggableAuthenticationModulesIP(ICredentials):
    """
    Twisted removed IPAM in 15, adding in Cowrie now
    """


@implementer(IPluggableAuthenticationModulesIP)
class PluggableAuthenticationModulesIP:
    """
    Twisted removed IPAM in 15, adding in Cowrie now
    """

    def __init__(self, username: str, pamConversion: Callable, ip: str) -> None:
        self.username: str = username
        self.pamConversion: Callable = pamConversion
        self.ip: str = ip


@implementer(IUsername)
class Username:
    def __init__(self, username: str):
        self.username: str = username


@implementer(IUsernamePasswordIP)
class UsernamePasswordIP:
    """
    This credential interface also provides an IP address
    """

    def __init__(self, username: str, password: str, ip: str) -> None:
        self.hashdb: dict[
            tuple[Union[Pattern[bytes], bytes], Union[Pattern[bytes], bytes]], bool
        ] = OrderedDict()
        self.username: str = username
        self.password: str = password

        
        self.hashPasswords: bool = CowrieConfig.getboolean(
            "honeypot", "hashPasswords", fallback=False
        )
        if self.hashPasswords:
            self.load()
            if self.check_login(username, password, ip):
                self.password = hashlib.sha256(password).hexdigest()

        self.ip: str = ip

    def load(self) -> None:
        """
        load the hashing patterns db. 
        """

        dblines: list[str]
        try:
            with open(
                "{}/hashdb.txt".format(CowrieConfig.get("honeypot", "etc_path"))
            ) as db:
                dblines = db.readlines()
        except OSError:
            log.msg("No hash patterns db detected.")
            dblines = []

        for user in dblines:
            if not user.startswith("#"):
                try:
                    login = user.split(":")[0].encode("utf8")
                    password = user.split(":")[2].strip().encode("utf8")
                except IndexError:
                    continue
                else:
                    self.addcombination(login, password)

    def re_or_bytes(self, rule: bytes) -> Union[Pattern[bytes], bytes]:
        """
        Convert a /.../ type rule to a regex, otherwise return the string as-is

        @param login: rule
        @type login: bytes
        """
        res = re.match(br"/(.+)/(i)?$", rule)
        if res:
            return re.compile(res.group(1), re.IGNORECASE if res.group(2) else 0)

        return rule

    def match_rule(
            self, rule: Union[bytes, Pattern[bytes]], input: bytes
        ) -> Union[bool, bytes]:
            if isinstance(rule, bytes):
                return rule in [b"*", input]
            else:
                return bool(rule.search(input))

    def check_login(
        self, thelogin: bytes, thepasswd: bytes, src_ip: str = "0.0.0.0"
    ) -> bool:
        """
        Check_login function from auth.py
        """
        for credentials, policy in self.hashdb.items():
            login: Union[bytes, Pattern[bytes]]
            passwd: Union[bytes, Pattern[bytes]]
            login, passwd = credentials

            if self.match_rule(login, thelogin):
                if self.match_rule(passwd, thepasswd):
                    return policy

        return False
    def addcombination(self, login: bytes, passwd: bytes) -> None:
        """
        All arguments are bytes

        @param login: user id
        @type login: bytes
        @param passwd: password
        @type passwd: bytes
        """
        user = self.re_or_bytes(login)

        if passwd[0] == ord("!"):
            policy = False
            passwd = passwd[1:]
        else:
            policy = True

        p = self.re_or_bytes(passwd)
        self.hashdb[(user, p)] = policy



    def checkPassword(self, password: str) -> bool:
        self.password = password
