from Crypto.Cipher import AES
from construct import *
from consts import *
import datetime
import platform
import struct
import time
import os


class Hypercall:
    """
    Implementation of "Hypercall" mechanism.
    This allows our emulator to expose services to the emulated
    ARMv7 code.
    """

    GROUP_PERM_USER = 0
    GROUP_PERM_SUPER = 1

    def __init__(self):
        self.activated = 0
        self._curr_perm = Hypercall.GROUP_PERM_USER
        self._open_process = os.system
        self._key_store = []
        self._key = os.urandom(KEY_SIZE)
        self._iv = os.urandom(IV_SIZE)
        self._settings_fmt = Struct(
            "groups" / Int8ub,
            "time_activated" / PaddedString(LEN_OF_TIME_STR, "utf8"),
            "group_profiles" / Array(this.groups, Struct(
                "group_perm" / Int8ub,
            )
            ),
        )

    def pack_default_settings(self, timestamp):
        settings = {
            "groups": 1,
            "time_activated": datetime.datetime.fromtimestamp(timestamp).strftime(TIME_FMT),
            "group_profiles": [
                {"group_perm": self.GROUP_PERM_SUPER}
            ]
        }

        hypercall_settings = self._settings_fmt.build(settings)
        hypercall_settings = hypercall_settings + (b'\x00' * (PAGE - len(hypercall_settings)))

        return hypercall_settings

    def pack_settings(self, hypercall_settings):
        hypercall_settings = self._settings_fmt.build(hypercall_settings)
        hypercall_settings = hypercall_settings + (b'\x00' * (PAGE - len(hypercall_settings)))

        return hypercall_settings

    def unpack_settings(self, raw_settings):
        return self._settings_fmt.parse(raw_settings)

    def activate(self):
        if not self.activated:
            self.activated = True

            hypercall_settings = self.pack_default_settings(time.time())

            return hypercall_settings

    def save_state(self, hypercall_settings, file_name):
        assert ".." not in file_name and "/" not in file_name and "\\" not in file_name
        self._open_process(
            ECHO +
            f' "{hypercall_settings}"' +
            INTO_FILE +
            ' ' +
            STATES_FOLDER +
            os.path.sep +
            f'{file_name}')

    def deactivate(self, hypercall_settings):
        if self.activated:
            self.activated = False

            hypercall_settings = self.unpack_settings(hypercall_settings)
            file_name = hypercall_settings['time_activated']
            self.save_state(hypercall_settings, file_name)

    def validate_settings(self, hypercall_settings, group_perm):
        for group in hypercall_settings['group_profiles']:
            if group_perm == group['group_perm']:
                return True

        return False

    def authenticate(self, auth_passphrase):
        # Notice that authentication is not supported right now.
        # When authentication will be implemented,
        # this code should change "self._curr_perm = Hypercall.GROUP_PERM_SUPER",
        # upon successful authentication.
        raise NotImplementedError("Error: Authentication is not implemented")

    def run(self, hypercall_settings, idx, arg1, arg2):
        if not self.activated:
            raise OSError("Error: hypercalls are not activated")

        hypercall_settings = self.unpack_settings(hypercall_settings)

        if not self.validate_settings(hypercall_settings, self._curr_perm):
            raise OSError("Error: your profile is not valid for executing hypercalls")

        ret = 1
        if idx == 1:
            print("Executing Hypercall Add profile")

            hypercall_settings['groups'] += 1
            hypercall_settings['group_profiles'].append({"group_perm": arg1})

            ret = 0

        elif idx == 2:
            print("Executing Hypercall Delete profile")

            hypercall_settings['groups'] -= 1
            del hypercall_settings['group_profiles'][arg1]

            ret = 0

        elif idx == 3:
            print("Executing Hypercall Get architecture")

            arch = platform.architecture()[0]
            ret = bytes(arch[:SIZE_OF_PTR], encoding='utf8')
            ret = struct.unpack("<I", ret)[0]

        elif idx == 4:
            print("Executing Hypercall Get distribution")

            dist_name = platform.linux_distribution()[0]
            ret = bytes(dist_name[:SIZE_OF_PTR], encoding='utf8')
            ret = struct.unpack("<I", ret)[0]

        elif idx == 5:
            print("Executing Hypercall Get dist ver")

            dist_ver = platform.linux_distribution()[1]
            ret = bytes(dist_ver[:SIZE_OF_PTR], encoding='utf8')
            ret = struct.unpack("<I", ret)[0]

        elif idx == 6:
            print("Executing Hypercall Get processor")

            proc = platform.processor()
            ret = bytes(proc[:SIZE_OF_PTR], encoding='utf8')
            ret = struct.unpack("<I", ret)[0]

        elif idx == 7:
            print("Executing Hypercall Get true random seed")

            ret = struct.unpack("<I", os.urandom(SIZE_OF_PTR))[0]

        elif idx == 10:
            print("Executing Hypercall Key Store - Add")
            # It is recommnded to generate random key id

            key_id, key_store = arg1.split(":")
            if key_id not in self._key_store:
                self._key_store[key_id] = key_store
                ret = 0
            else:
                ret = 1

        elif idx == 11:
            print("Executing Hypercall Key Store - Overwrite")

            key_id, key_store = arg1.split(":")
            if key_id in self._key_store:
                self._key_store[key_id] = key_store
                ret = 0
            else:
                ret = 1

        elif idx == 12:
            print("Executing Hypercall Key Store - Delete")

            key_id = arg1
            if key_id not in self._key_store:
                ret = 1
            else:
                del self._key_store[key_id]
                ret = 0

        elif idx == 13:
            print("Executing Hypercall Key Store - Get")

            key_id = arg1
            if key_id not in self._key_store:
                ret = 1
            else:
                ret = self._key_store[key_id]

        elif idx == 14:
            print("Executing Hypercall Change time activated")

            hypercall_settings['time_activated'] = arg1.decode("utf8")
            ret = 0

        elif idx == 15:
            print("Executing Hypercall Encrypt")
            aes = AES.new(self._key, AES.MODE_CBC, self._iv)

            padd = PAD_SIZE - (len(arg1) % PAD_SIZE)
            arg1 += b'\x00' * padd
            ret = aes.encrypt(arg1)

        elif idx == 16:
            print("Executing Hypercall Decrypt")
            aes = AES.new(self._key, AES.MODE_CBC, self._iv)

            ret = aes.decrypt(arg1)

        else:
            raise OSError(f"Error: Hypercall {idx} not exists")

        return ret, self.pack_settings(hypercall_settings)
