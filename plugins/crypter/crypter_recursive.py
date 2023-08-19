import os
import ast
import pyaes
from nuitka.plugins.PluginBase import NuitkaPluginBase

class RecursiveEncryptionPlugin(NuitkaPluginBase):
    plugin_name = __name__.split(".")[-1]

    def __init__(self, trace_my_plugin):
        self.check = trace_my_plugin
        self.info(f"'trace' is set to '{self.check}'")

    @classmethod
    def addPluginCommandLineOptions(cls, group):
        group.add_option(
            "--trace-my-rec",
            action="store_true",
            dest="trace_my_plugin",
            default=False,
            help="Enable tracing for the RecursiveEncryptionPlugin."
        )

    def aes_encrypt(self, plaintext, key):
        cipher = pyaes.AESModeOfOperationCTR(key.encode())
        ciphertext = cipher.encrypt(plaintext.encode())
        return ciphertext

    def onModuleSourceCode(self, module_name, source_code):
        if self.check:
            self.info(f"Processing module '{module_name}'")

            # AES encrypt the entire source code
            aes_key = os.urandom(32)  # Generate a random AES key
            obfuscated_code = self.aes_encrypt(source_code, aes_key)

            # Create a hook to decode and execute the AES-obfuscated code during runtime
            runtime_hook = f'''
import pyaes

def decode_and_execute():
    aes_key = {aes_key}
    obfuscated_code = {obfuscated_code}
    cipher = pyaes.AESModeOfOperationCTR(aes_key)
    decoded_code = cipher.decrypt(obfuscated_code).decode()
    exec(decoded_code)

decode_and_execute()
'''

            return runtime_hook

        return source_code
