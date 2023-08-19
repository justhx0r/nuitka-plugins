import os
import ast
import random
import string
from nuitka.plugins.PluginBase import NuitkaPluginBase
import tinyaes

class MyEncryptionPlugin(NuitkaPluginBase):
    plugin_name = __name__.split(".")[-1]

    def __init__(self, trace_my_plugin):
        self.check = trace_my_plugin
        self.info(f"'trace' is set to '{self.check}'")
        self.additional_imports = set()
        self.name_mapping = {}
        self.enable_noise_injection = True
        self.enable_string_renaming = True
        self.enable_in_memory_encryption = True

    @classmethod
    def addPluginCommandLineOptions(cls, group):
        group.add_option(
            "--trace-my-plugin",
            action="store_true",
            dest="trace_my_plugin",
            default=False,
            help="Enable tracing for the MyEncryptionPlugin."
        )

    def shuffle_characters(self, text):
        characters = list(text)
        random.shuffle(characters)
        return ''.join(characters)

    def obfuscate_string(self, text):
        shuffled = self.shuffle_characters(text)
        return shuffled

    def aes_encrypt(self, plaintext, key):
        cipher = tinyaes.AES256Cipher(key.encode())
        ciphertext = cipher.encrypt(plaintext.encode())
        return ciphertext

    def aes_decrypt(self, ciphertext, key):
        cipher = tinyaes.AES256Cipher(key.encode())
        plaintext = cipher.decrypt(ciphertext).decode()
        return plaintext

    def inject_random_noise(self, code):
        noise_functions = [
            "math.erf(random.uniform(-1, 1))",
            "math.fmod(random.uniform(1, 10), 2)",
        ]

        code_lines = code.split("\n")
        self.analyze_imports(code)

        required_imports = ["import sys", "import math", "import random", "import string"]
        for import_line in required_imports:
            if import_line not in code_lines:
                code_lines.insert(0, import_line)

        new_code_lines = []
        for line in code_lines:
            new_code_lines.append(line)
            if self.enable_noise_injection:
                num_noise_lines = random.randint(3, 11)
                for _ in range(num_noise_lines):
                    noise_line = random.choice(noise_functions)
                    new_code_lines.append(noise_line)

        code = "\n".join(new_code_lines)
        return code

    def random_string(self, length=42):
        return ''.join(random.choice(string.ascii_letters) for _ in range(length))

    def analyze_imports(self, source_code):
        tree = ast.parse(source_code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.additional_imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module_name = node.module
                for alias in node.names:
                    if alias.name == "*":
                        self.additional_imports.add(module_name)
                    else:
                        self.additional_imports.add(f"{module_name}.{alias.name}")

    def rename_symbols(self, source_code):
        tree = ast.parse(source_code)

        class RandomNameGenerator:
            def __init__(self):
                self.used_names = set()

            def generate(self):
                while True:
                    name = self._random_name()
                    if name not in self.used_names:
                        self.used_names.add(name)
                        return name

            def _random_name(self):
                return self.random_string(random.randint(5, 15))

        name_generator = RandomNameGenerator()

        def rename_node(node):
            if isinstance(node, ast.Name):
                if node.id not in self.name_mapping:
                    self.name_mapping[node.id] = name_generator.generate()
                node.id = self.name_mapping[node.id]
            elif isinstance(node, ast.FunctionDef):
                if node.name not in self.name_mapping:
                    self.name_mapping[node.name] = name_generator.generate()
                node.name = self.name_mapping[node.name]
            elif isinstance(node, ast.ClassDef):
                if node.name not in self.name_mapping:
                    self.name_mapping[node.name] = name_generator.generate()
                node.name = self.name_mapping[node.name]

        for node in ast.walk(tree):
            rename_node(node)

        return ast.dump(tree)

    def onModuleSourceCode(self, module_name, source_code):
        if module_name == "__main__" and self.check:
            self.info("Original source code:")
            self.info(source_code)

            # Analyze imports before obfuscating
            self.analyze_imports(source_code)

            # Obfuscate strings in the source code
            obfuscated_code = source_code
            if self.enable_string_renaming:
                for line in source_code.splitlines():
                    if '"' in line:
                        parts = line.split('"')
                        obfuscated_parts = [self.obfuscate_string(part) if '"' in part else part for part in parts]
                        obfuscated_line = ''.join(obfuscated_parts)
                        obfuscated_code = obfuscated_code.replace(line, obfuscated_line)

            # Rename symbols (variables, functions, classes)
            obfuscated_code = self.rename_symbols(obfuscated_code)

            # Inject random noise into the obfuscated code
            if self.enable_noise_injection:
                obfuscated_code = self.inject_random_noise(obfuscated_code)

            # AES encrypt the entire obfuscated code
            aes_key = self.random_string(32)  # Generate a random AES key
            obfuscated_code = self.aes_encrypt(obfuscated_code, aes_key)

            # Add necessary imports to the plugin's imports
            for import_name in self.additional_imports:
                self.additionalModuleFiles.append(import_name)

            # Create a hook to decode and execute the AES-obfuscated code during runtime
            runtime_hook = f'''
import sys

def {self.random_string()}_decode(obfuscated_str, aes_key):
    import tinyaes
    cipher = tinyaes.AES256Cipher(aes_key.encode())
    decoded_str = cipher.decrypt(obfuscated_str).decode()
    return decoded_str

def {self.random_string()}_execute():
    aes_key = "{aes_key}"
    obfuscated_code = "{obfuscated_code}"
    decoded_code = {self.random_string()}_decode(obfuscated_code, aes_key)
    exec(decoded_code)

{self.random_string()}_execute()
'''

            return runtime_hook

        return source_code

    def suppressBuiltinImportWarning(self, module_name, source_ref):
        if module_name == "base64":
            return True

        return False
